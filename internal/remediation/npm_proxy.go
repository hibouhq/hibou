package remediation

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"deps.dev/util/resolve"
)

// npmRegistryProxy is job-scoped, not a persistent IDE daemon. It applies the
// same namespace gate to native npm requests as to SCALIBR metadata lookups.
type npmRegistryProxy struct {
	URL     string
	server  *http.Server
	mu      sync.Mutex
	failure error
}

func startNPMProxy(ctx context.Context, match MatchPackages) (*npmRegistryProxy, error) {
	return startNPMProxyWithClient(ctx, match, nil)
}

func startNPMProxyWithClient(ctx context.Context, match MatchPackages, upstream *http.Client) (*npmRegistryProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	prefix := "/" + rand.Text() + "/"
	p := &npmRegistryProxy{URL: "http://" + listener.Addr().String() + prefix}
	guard := &namespaceGuardResolver{match: match, checked: map[string]bool{}}
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout: time.Second, MaxIdleConnsPerHost: 4,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("registry redirects are not approved") }}
	if upstream != nil {
		client = upstream
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		requestPath := "/" + strings.TrimPrefix(r.URL.Path, prefix)
		fail := func(err error, code int) {
			p.mu.Lock()
			if p.failure == nil {
				p.failure = err
			}
			p.mu.Unlock()
			http.Error(w, "registry request could not be approved", code)
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			fail(errors.New("unexpected registry method"), http.StatusMethodNotAllowed)
			return
		}
		if r.URL.IsAbs() || len(r.URL.Path) > 4096 || len(r.URL.RawQuery) > 4096 {
			fail(errors.New("invalid registry request"), http.StatusBadRequest)
			return
		}
		segments := strings.Split(strings.Trim(requestPath, "/"), "/")
		if len(segments) == 0 || segments[0] == "" || strings.HasPrefix(segments[0], "-") {
			fail(errors.New("unsupported registry request"), http.StatusBadRequest)
			return
		}
		for _, s := range segments {
			if s == "." || s == ".." || strings.ContainsAny(s, "\\\x00\r\n") {
				fail(errors.New("invalid registry path"), http.StatusBadRequest)
				return
			}
		}
		name := segments[0]
		if strings.HasPrefix(name, "@") {
			if len(segments) < 2 {
				fail(errors.New("incomplete scoped package"), http.StatusBadRequest)
				return
			}
			name += "/" + segments[1]
		}
		requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		stop := context.AfterFunc(r.Context(), cancel)
		defer stop()
		defer cancel()
		if err := guard.check(requestCtx, resolve.PackageKey{System: resolve.NPM, Name: name}); err != nil {
			fail(err, http.StatusForbidden)
			return
		}
		target := &url.URL{Scheme: "https", Host: "registry.npmjs.org", Path: requestPath, RawQuery: r.URL.RawQuery}
		req, err := http.NewRequestWithContext(requestCtx, r.Method, target.String(), nil)
		if err != nil {
			fail(err, http.StatusBadRequest)
			return
		}
		req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
		// #nosec G704 -- fixed HTTPS registry origin, no redirects or forwarded credentials; only the approved package path varies.
		resp, err := client.Do(req)
		if err != nil {
			fail(err, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fail(errors.New("registry metadata or package unavailable"), http.StatusBadGateway)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusOK)
			return
		}
		if !strings.Contains(requestPath, "/-/") {
			data, err := io.ReadAll(io.LimitReader(resp.Body, MaxFileBytes+1))
			if err != nil || len(data) > MaxFileBytes {
				fail(errors.New("registry metadata exceeds the profile limit"), http.StatusBadGateway)
				return
			}
			data, err = checkedNPMMetadata(data)
			if err != nil {
				fail(err, http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write(data); err != nil {
				p.mu.Lock()
				if p.failure == nil {
					p.failure = err
				}
				p.mu.Unlock()
			}
			return
		}
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		limit := int64(MaxFileBytes)
		if strings.Contains(requestPath, "/-/") {
			limit = 128 << 20
		}
		n, err := io.Copy(w, io.LimitReader(resp.Body, limit))
		if err != nil || n >= limit {
			p.mu.Lock()
			if p.failure == nil {
				if err != nil {
					p.failure = err
				} else {
					p.failure = errors.New("registry response exceeds the profile limit")
				}
			}
			p.mu.Unlock()
		}

	})
	p.server = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		if err := p.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.mu.Lock()
			p.failure = err
			p.mu.Unlock()
		}
		transport.CloseIdleConnections()
	}()
	return p, nil
}

func (p *npmRegistryProxy) close() error {
	err := p.server.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	return errors.Join(err, p.failure)
}
