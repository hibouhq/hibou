// Package lsp implements `hibou lsp`, the language server shared by the IDE
// extensions (ADR-042). It speaks the subset of the Language Server Protocol
// the clients use over stdio, plus a few hibou/* requests for their panels.
package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// JSON-RPC error codes used by this server.
const (
	codeParseError           = -32700
	codeInvalidRequest       = -32600
	codeMethodNotFound       = -32601
	codeInvalidParams        = -32602
	codeInternalError        = -32603
	codeServerNotInitialized = -32002
	codeRequestCancelled     = -32800
)

// maxMessageBytes bounds a single incoming message so a broken client cannot
// make the server allocate without limit. Full-document syncs of large files
// stay well below it.
const maxMessageBytes = 64 << 20

type message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *rpcError        `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// handlerFunc answers one request or notification. For a notification the
// result is discarded.
type handlerFunc func(ctx context.Context, method string, params json.RawMessage) (any, error)

// conn is a JSON-RPC 2.0 connection with LSP base-protocol framing
// (Content-Length headers). Requests from the client run concurrently;
// notifications run in arrival order, because document syncs must not be
// reordered.
type conn struct {
	r       *bufio.Reader
	w       io.Writer
	writeMu sync.Mutex
	handler handlerFunc

	nextID  atomic.Int64
	pendMu  sync.Mutex
	pending map[string]chan *message

	cancelMu sync.Mutex
	cancels  map[string]context.CancelFunc
}

func newConn(r io.Reader, w io.Writer, handler handlerFunc) *conn {
	return &conn{
		r:       bufio.NewReader(r),
		w:       w,
		handler: handler,
		pending: map[string]chan *message{},
		cancels: map[string]context.CancelFunc{},
	}
}

// run reads messages until the input closes or ctx ends.
func (c *conn) run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		msg, err := c.read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			var rpcErr *rpcError
			if errors.As(err, &rpcErr) {
				_ = c.write(&message{JSONRPC: "2.0", ID: nullID(), Error: rpcErr})
				continue
			}
			return err
		}
		c.dispatch(ctx, msg)
	}
}

func (c *conn) dispatch(ctx context.Context, msg *message) {
	switch {
	case msg.Method == "" && msg.ID != nil:
		// Response to a request we sent.
		key := string(*msg.ID)
		c.pendMu.Lock()
		ch := c.pending[key]
		delete(c.pending, key)
		c.pendMu.Unlock()
		if ch != nil {
			ch <- msg
		}
	case msg.Method == "$/cancelRequest":
		var p struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(msg.Params, &p) == nil {
			c.cancelMu.Lock()
			if cancel := c.cancels[string(p.ID)]; cancel != nil {
				cancel()
			}
			c.cancelMu.Unlock()
		}
	case msg.ID == nil:
		_, _ = c.handler(ctx, msg.Method, msg.Params)
	default:
		key := string(*msg.ID)
		reqCtx, cancel := context.WithCancel(ctx)
		c.cancelMu.Lock()
		c.cancels[key] = cancel
		c.cancelMu.Unlock()
		go func() {
			defer func() {
				c.cancelMu.Lock()
				delete(c.cancels, key)
				c.cancelMu.Unlock()
				cancel()
			}()
			result, err := c.handler(reqCtx, msg.Method, msg.Params)
			c.reply(msg.ID, result, err, reqCtx.Err() != nil)
		}()
	}
}

func (c *conn) reply(id *json.RawMessage, result any, err error, cancelled bool) {
	resp := &message{JSONRPC: "2.0", ID: id}
	if err != nil {
		var rpcErr *rpcError
		switch {
		case errors.As(err, &rpcErr):
			resp.Error = rpcErr
		case cancelled:
			resp.Error = &rpcError{Code: codeRequestCancelled, Message: "request cancelled"}
		default:
			resp.Error = &rpcError{Code: codeInternalError, Message: err.Error()}
		}
	} else {
		data, mErr := json.Marshal(result)
		if mErr != nil {
			resp.Error = &rpcError{Code: codeInternalError, Message: mErr.Error()}
		} else {
			resp.Result = data
		}
	}
	_ = c.write(resp)
}

// notify sends a notification to the client.
func (c *conn) notify(method string, params any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return c.write(&message{JSONRPC: "2.0", Method: method, Params: data})
}

// call sends a request to the client and waits for its response.
func (c *conn) call(ctx context.Context, method string, params any, out any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	id := json.RawMessage(strconv.FormatInt(c.nextID.Add(1), 10))
	ch := make(chan *message, 1)
	c.pendMu.Lock()
	c.pending[string(id)] = ch
	c.pendMu.Unlock()

	if err := c.write(&message{JSONRPC: "2.0", ID: &id, Method: method, Params: data}); err != nil {
		c.pendMu.Lock()
		delete(c.pending, string(id))
		c.pendMu.Unlock()
		return err
	}
	select {
	case <-ctx.Done():
		c.pendMu.Lock()
		delete(c.pending, string(id))
		c.pendMu.Unlock()
		return ctx.Err()
	case resp := <-ch:
		if resp.Error != nil {
			return resp.Error
		}
		if out != nil && len(resp.Result) > 0 {
			return json.Unmarshal(resp.Result, out)
		}
		return nil
	}
}

func (c *conn) read() (*message, error) {
	length := -1
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed header %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid Content-Length %q", value)
			}
			length = n
		}
	}
	if length < 0 {
		return nil, errors.New("missing Content-Length header")
	}
	if length > maxMessageBytes {
		return nil, fmt.Errorf("message of %d bytes exceeds the %d-byte limit", length, maxMessageBytes)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return nil, err
	}
	var msg message
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, &rpcError{Code: codeParseError, Message: err.Error()}
	}
	return &msg, nil
}

func (c *conn) write(msg *message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := fmt.Fprintf(c.w, "Content-Length: %d\r\n\r\n", len(data)); err != nil {
		return err
	}
	_, err = c.w.Write(data)
	return err
}

func nullID() *json.RawMessage {
	id := json.RawMessage("null")
	return &id
}
