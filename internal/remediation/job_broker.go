package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// JobBroker exposes identities-only matching and the approved public registry
// over a private job socket. Never mount this socket where dependency tools run.
type JobBroker struct {
	server *http.Server
	proxy  *npmRegistryProxy
	socket string
}

func StartJobBroker(ctx context.Context, socket string, match MatchPackages) (*JobBroker, error) {
	if match == nil {
		return nil, ErrAdvisoryEvidence
	}
	proxy, err := startNPMProxy(ctx, match)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		_ = proxy.close()
		return nil, err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		_ = proxy.close()
		return nil, err
	}
	b := &JobBroker{proxy: proxy, socket: socket}
	b.server = &http.Server{Handler: jobBrokerHandler(proxy, match), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = b.server.Serve(listener) }()
	return b, nil
}

// ManagedBrokerHandler is mounted behind a shared workload broker's per-attempt
// authentication, UID binding, lease fencing and request budgets.
func ManagedBrokerHandler(ctx context.Context, match MatchPackages, upstream *http.Client) (http.Handler, func() error, error) {
	if match == nil || upstream == nil {
		return nil, nil, errors.New("managed matching and approved mirror transport are required")
	}
	proxy, err := startNPMProxyWithClient(ctx, match, upstream)
	if err != nil {
		return nil, nil, err
	}
	return jobBrokerHandler(proxy, match), proxy.close, nil
}

func jobBrokerHandler(proxy *npmRegistryProxy, match MatchPackages) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/match", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Purls []string `json:"purls"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&req) != nil || len(req.Purls) == 0 || len(req.Purls) > 5000 {
			http.Error(w, "invalid identities", http.StatusBadRequest)
			return
		}
		for _, identity := range req.Purls {
			if len(identity) > 2048 || !strings.HasPrefix(identity, "pkg:npm/") {
				http.Error(w, "npm identities required", http.StatusBadRequest)
				return
			}
		}
		result, err := match(r.Context(), req.Purls)
		if err != nil {
			http.Error(w, "authoritative matching unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/registry/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "read-only registry", http.StatusMethodNotAllowed)
			return
		}
		target := proxy.URL + strings.TrimPrefix(r.URL.EscapedPath(), "/registry/")
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		// #nosec G704 -- origin and nonce prefix come only from this job's trusted 127.0.0.1 listener; request data is appended path/query, never authority.
		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, nil)
		if err != nil {
			http.Error(w, "invalid registry request", http.StatusBadRequest)
			return
		}
		client := &http.Client{Timeout: 40 * time.Second, CheckRedirect: refuseJobRedirect,
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 30 * time.Second}}
		// #nosec G704 -- fixed job-local nonce-protected proxy origin, no environment proxy or redirects; downstream proxy enforces public origin, namespace and metadata checks.
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "registry unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 128<<20))
	})
	return mux
}

func (b *JobBroker) Close() error {
	err := b.server.Close()
	proxyErr := b.proxy.close()
	_ = os.Remove(b.socket)
	return errors.Join(err, proxyErr)
}

func refuseJobRedirect(*http.Request, []*http.Request) error {
	return errors.New("job broker redirects are forbidden")
}

func unixJobClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 45 * time.Second, CheckRedirect: refuseJobRedirect,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
			},
			ResponseHeaderTimeout: 40 * time.Second,
		},
	}
}

func JobMatchClient(socket string) MatchPackages {
	client := unixJobClient(socket)
	return func(ctx context.Context, purls []string) ([]AdvisoryMatch, error) {
		data, err := json.Marshal(struct {
			Purls []string `json:"purls"`
		}{purls})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://broker/match", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, ErrAdvisoryEvidence
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, MaxInputBytes+1))
		if err != nil || len(data) > MaxInputBytes {
			return nil, errors.New("broker matching response exceeds limit")
		}
		var matches []AdvisoryMatch
		if err := json.Unmarshal(data, &matches); err != nil {
			return nil, err
		}
		return matches, nil
	}
}

type jobRegistryTransport struct{ transport http.RoundTripper }

func (t jobRegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "registry.npmjs.org" || req.URL.User != nil ||
		(req.Method != http.MethodGet && req.Method != http.MethodHead) {
		return nil, errors.New("registry origin or method is not approved")
	}
	clone := req.Clone(req.Context())
	target := *req.URL
	target.Scheme, target.Host = "http", "broker"
	target.Path, target.RawPath = "/registry"+target.Path, ""
	clone.URL, clone.Host = &target, "broker"
	clone.Header = make(http.Header)
	return t.transport.RoundTrip(clone)
}

// JobRegistryClient forwards only the fixed public npm origin; neither
// credentials nor arbitrary URL destinations can cross the socket.
func JobRegistryClient(socket string) *http.Client {
	client := unixJobClient(socket)
	client.Transport = jobRegistryTransport{client.Transport}
	return client
}
