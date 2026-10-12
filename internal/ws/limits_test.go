package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
)

// A client cannot pin unbounded topic state: overlong topics are ignored and
// the set stops growing at the cap (§6 D9).
func TestSubscribeCapsTopicCountAndLength(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	c := &client{topics: map[string]bool{}}

	topics := make([]string, 0, maxTopicsPerClient+20)
	topics = append(topics, strings.Repeat("x", maxTopicLength+1))
	for i := 0; i < maxTopicsPerClient+19; i++ {
		topics = append(topics, fmt.Sprintf("topic.%d", i))
	}
	payload, _ := json.Marshal(subscriptionPayload{Topics: topics})
	hub.handleClientMessage(context.Background(), c, Message{Type: "topic.subscribe", Payload: payload})

	if len(c.topics) != maxTopicsPerClient {
		t.Fatalf("topics = %d, want cap %d", len(c.topics), maxTopicsPerClient)
	}
	if c.topics[strings.Repeat("x", maxTopicLength+1)] {
		t.Fatal("overlong topic was accepted")
	}

	// Unsubscribing frees room again.
	payload, _ = json.Marshal(subscriptionPayload{Topics: []string{"topic.0"}})
	hub.handleClientMessage(context.Background(), c, Message{Type: "topic.unsubscribe", Payload: payload})
	payload, _ = json.Marshal(subscriptionPayload{Topics: []string{"gate.updated"}})
	hub.handleClientMessage(context.Background(), c, Message{Type: "topic.subscribe", Payload: payload})
	if !c.topics["gate.updated"] {
		t.Fatal("subscribe after unsubscribe was refused")
	}
}

// One user cannot hold more than the per-user limit of sockets; others are
// unaffected.
func TestRegisterLimitedCapsConnectionsPerUser(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	userID := uuid.New()
	const limit = 2

	type result struct{ ok bool }
	results := make(chan result, 8)
	var held sync.WaitGroup
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		owner := userID
		if r.URL.Query().Get("other") != "" {
			owner = uuid.New()
		}
		c, ok := hub.registerLimited(conn, owner, limit)
		results <- result{ok: ok}
		if !ok {
			_ = conn.Close(websocket.StatusPolicyViolation, "limit")
			return
		}
		held.Add(1)
		defer held.Done()
		<-release
		hub.Unregister(c)
	}))
	defer server.Close()
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	dial := func(suffix string) {
		conn, resp, err := websocket.Dial(ctx, url+suffix, nil)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.CloseNow() })
	}

	want := []bool{true, true, false}
	for i, expected := range want {
		dial("")
		select {
		case got := <-results:
			if got.ok != expected {
				t.Fatalf("connection %d registered = %v, want %v", i, got.ok, expected)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for registration")
		}
	}
	if count := hub.userConnectionCount(userID); count != limit {
		t.Fatalf("held connections = %d, want %d", count, limit)
	}

	dial("?other=1")
	if got := <-results; !got.ok {
		t.Fatal("another user's connection was refused")
	}
}

type fakePinger struct {
	err    error
	mu     sync.Mutex
	closed bool
	pings  int
}

func (p *fakePinger) Ping(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pings++
	return p.err
}

func (p *fakePinger) Close(websocket.StatusCode, string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return nil
}

// A peer that stops answering pings is closed, which unblocks the handler's
// read loop and frees its slot.
func TestKeepAliveClosesUnresponsivePeer(t *testing.T) {
	peer := &fakePinger{err: errors.New("pong timeout")}
	done := make(chan struct{})
	go func() {
		keepAlive(context.Background(), peer, 5*time.Millisecond, 5*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keepAlive did not return after a failed ping")
	}
	if !peer.closed {
		t.Fatal("unresponsive peer was not closed")
	}
}

func TestKeepAlivePingsUntilCancelled(t *testing.T) {
	peer := &fakePinger{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		keepAlive(ctx, peer, 2*time.Millisecond, time.Second)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.pings == 0 {
		t.Fatal("no ping sent")
	}
	if peer.closed {
		t.Fatal("healthy peer was closed")
	}
}

// API tokens are refused on /ws: an org-owned token has no user, and running
// the socket as its creator ignored the token scope (A7).
func TestHTTPHandlerRefusesBearerTokens(t *testing.T) {
	hub := NewHub(zerolog.Nop())
	handler := hub.HTTPHandler(auth.New(auth.Config{}, nil), nil)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/ws", nil)
	request.Header.Set("Authorization", "Bearer hib_whatever")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "API tokens are not accepted") {
		t.Fatalf("body = %q, want the token refusal", recorder.Body.String())
	}
}
