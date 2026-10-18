package devicelogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

func TestRequestCodeAndPollSuccess(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/device/code":
			var req CodeRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.ClientID != ClientVSCode || req.Scope != "read-only" || req.ClientName != "devbox" {
				t.Errorf("code request = %+v", req)
			}
			_ = json.NewEncoder(w).Encode(Authorization{DeviceCode: "dc", UserCode: "BCDFGHJK", ExpiresIn: 600, Interval: 5})
		case "/api/v1/auth/device/token":
			var req TokenRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.GrantType != GrantType || req.DeviceCode != "dc" || req.ClientID != ClientVSCode {
				t.Errorf("token request = %+v", req)
			}
			n := polls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			switch n {
			case 1:
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(ErrorResponse{Error: ErrCodePending})
			case 2:
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(ErrorResponse{Error: ErrCodeSlowDown})
			default:
				_ = json.NewEncoder(w).Encode(Token{AccessToken: "hibou_pat_x", TokenType: "Bearer", Orgs: "memberships"})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var intervals []time.Duration
	c := &Client{Server: srv.URL + "/", sleep: func(_ context.Context, d time.Duration) error {
		intervals = append(intervals, d)
		return nil
	}}
	auth, err := c.RequestCode(context.Background(), Request{ClientID: ClientVSCode, ClientName: "devbox", Preset: "read-only"})
	if err != nil {
		t.Fatalf("RequestCode: %v", err)
	}
	tok, err := c.Poll(context.Background(), auth)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if tok.AccessToken != "hibou_pat_x" || polls.Load() != 3 {
		t.Fatalf("token = %+v after %d polls", tok, polls.Load())
	}
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}
	if len(intervals) != len(want) {
		t.Fatalf("intervals = %v, want %v", intervals, want)
	}
	for i := range want {
		if intervals[i] != want[i] {
			t.Fatalf("intervals = %v, want %v (slow_down adds 5s)", intervals, want)
		}
	}
}

func TestPollTerminalErrors(t *testing.T) {
	for code, want := range map[string]error{ErrCodeAccessDenied: ErrDenied, ErrCodeExpired: ErrExpired} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(ErrorResponse{Error: code})
		}))
		c := &Client{Server: srv.URL, sleep: noSleep}
		_, err := c.Poll(context.Background(), &Authorization{DeviceCode: "dc", Interval: 1, ExpiresIn: 60})
		srv.Close()
		if !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", code, err, want)
		}
	}
}

func TestRequestCodeOldServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := &Client{Server: srv.URL}
	if _, err := c.RequestCode(context.Background(), Request{ClientID: ClientCLI}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func TestRequestCodeUnknownScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"scope must be cli or read-only"}`))
	}))
	defer srv.Close()
	c := &Client{Server: srv.URL}
	_, err := c.RequestCode(context.Background(), Request{ClientID: ClientVSCode, Preset: "triage"})
	if !errors.Is(err, ErrInvalidScope) || !strings.Contains(err.Error(), "cli or read-only") {
		t.Fatalf("err = %v, want ErrInvalidScope with the server's description", err)
	}
}

func TestPollStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Client{Server: "http://127.0.0.1:1", sleep: noSleep}
	if _, err := c.Poll(ctx, &Authorization{DeviceCode: "dc", Interval: 1, ExpiresIn: 60}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
