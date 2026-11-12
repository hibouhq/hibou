package workload

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

type attempt struct {
	mu                           sync.Mutex
	ctx                          context.Context
	cancel                       context.CancelFunc
	token, fence, jobUID, podUID string
	input, output                []byte
	submitted                    bool
	handler                      http.Handler
	maxInput, maxOutput          int64
	validate                     func(context.Context, string) error
	sem                          chan struct{}
}

// Broker must be mounted only on the controller's authenticated TLS listener.
// Each capability is ephemeral, attempt/fence scoped and revoked before cleanup.
// The delegated Handler is trusted domain code, never a generic reverse proxy.
type Broker struct {
	mu       sync.RWMutex
	attempts map[string]*attempt
}

func NewBroker() *Broker                    { return &Broker{attempts: make(map[string]*attempt)} }
func (b *Broker) add(id string, a *attempt) { b.mu.Lock(); b.attempts[id] = a; b.mu.Unlock() }
func (b *Broker) revoke(id string) {
	b.mu.Lock()
	a := b.attempts[id]
	delete(b.attempts, id)
	b.mu.Unlock()
	if a != nil {
		a.cancel()
		a.mu.Lock()
		a.input = nil
		a.output = nil
		a.mu.Unlock()
	}
}
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || r.URL.RawQuery != "" || len(r.URL.Path) > 2048 {
		http.Error(w, "invalid transport", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/v1/workloads/"), "/", 2)
	if !strings.HasPrefix(r.URL.Path, "/v1/workloads/") || len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	if r.URL.RawPath != "" && (!strings.HasPrefix(parts[1], "proxy/registry/") ||
		!strings.HasPrefix(r.URL.RawPath, "/v1/workloads/"+parts[0]+"/proxy/registry/")) {
		http.Error(w, "invalid escaped route", http.StatusBadRequest)
		return
	}
	b.mu.RLock()
	a := b.attempts[parts[0]]
	b.mu.RUnlock()
	if a == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	select {
	case <-a.ctx.Done():
		http.Error(w, "expired", http.StatusGone)
		return
	default:
	}
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	// UID validation is a live API lookup, not an assertion based on pod labels.
	if err := a.validate(ctx, r.Header.Get("X-Hibou-Pod-UID")); err != nil {
		http.Error(w, "identity unavailable", http.StatusForbidden)
		return
	}
	switch {
	case parts[1] == "input" && r.Method == http.MethodGet:
		a.mu.Lock()
		if a.ctx.Err() != nil {
			a.mu.Unlock()
			http.Error(w, "expired", http.StatusGone)
			return
		}
		input := a.input
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(input)
	case parts[1] == "output" && r.Method == http.MethodPost:
		data, err := readBounded(r.Body, a.maxOutput)
		if err != nil {
			http.Error(w, "output exceeds bounds", http.StatusRequestEntityTooLarge)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.ctx.Err() != nil {
			http.Error(w, "expired", http.StatusGone)
			return
		}
		if a.submitted {
			http.Error(w, "already submitted", http.StatusConflict)
			return
		}
		a.output = data
		a.submitted = true
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(parts[1], "proxy/") && a.handler != nil:
		data, err := readBounded(r.Body, a.maxInput)
		if err != nil {
			http.Error(w, "request exceeds bounds", http.StatusRequestEntityTooLarge)
			return
		}
		proxy := r.Clone(ctx)
		u := *r.URL
		u.Path = "/" + strings.TrimPrefix(parts[1], "proxy/")
		u.RawPath = ""
		if r.URL.RawPath != "" {
			u.RawPath = strings.TrimPrefix(r.URL.RawPath, "/v1/workloads/"+parts[0]+"/proxy")
		}
		proxy.URL = &u
		proxy.RequestURI = u.Path
		proxy.Body = io.NopCloser(bytes.NewReader(data))
		proxy.ContentLength = int64(len(data))
		// Capability and caller-controlled forwarding/auth headers never reach
		// domain handlers, which resolve credentials from their own bound scope.
		proxy.Header = make(http.Header)
		for _, k := range []string{"Content-Type", "Accept"} {
			if v := r.Header.Get(k); len(v) <= 256 {
				proxy.Header.Set(k, v)
			}
		}
		out := &boundedResponse{header: make(http.Header), max: a.maxOutput}
		a.handler.ServeHTTP(out, proxy)
		if ctx.Err() != nil {
			http.Error(w, "expired", http.StatusGone)
			return
		}
		if out.overflow {
			http.Error(w, "response exceeds bounds", http.StatusBadGateway)
			return
		}
		if v := out.header.Get("Content-Type"); v != "" {
			w.Header().Set("Content-Type", v)
		}
		if out.code == 0 {
			out.code = 200
		}
		w.WriteHeader(out.code)
		_, _ = w.Write(out.body.Bytes())
	default:
		http.NotFound(w, r)
	}
}
func readBounded(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, errors.New("body exceeds limit")
	}
	return b, nil
}

type boundedResponse struct {
	header   http.Header
	body     bytes.Buffer
	code     int
	max      int64
	overflow bool
}

func (w *boundedResponse) Header() http.Header { return w.header }
func (w *boundedResponse) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}
func (w *boundedResponse) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	if int64(w.body.Len()+len(p)) > w.max {
		w.overflow = true
		return 0, errors.New("response exceeds limit")
	}
	return w.body.Write(p)
}
