package workload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
)

// WorkerTransport is the only supported source/result transport for the
// disposable launcher. It has no Kubernetes/forge/database credentials.
type WorkerTransport struct {
	base, token, podUID string
	http                *http.Client
}

func NewWorkerTransport(endpoint, token, ca, podUID string) (*WorkerTransport, error) {
	u, err := secureURL(endpoint)
	if err != nil || !strings.HasPrefix(u.Path, "/v1/workloads/") || strings.Contains(strings.TrimPrefix(u.Path, "/v1/workloads/"), "/") ||
		len(strings.TrimPrefix(u.Path, "/v1/workloads/")) != 32 || !boundedString(token, 128) || !boundedString(podUID, 128) {
		return nil, errors.New("invalid worker capability configuration")
	}
	h, err := tlsClient(ca)
	if err != nil {
		return nil, err
	}
	return &WorkerTransport{endpoint, token, podUID, h}, nil
}
func (w *WorkerTransport) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if len(body) > MaxBodyBytes {
		return nil, errors.New("worker request exceeds limit")
	}
	req, err := http.NewRequestWithContext(ctx, method, w.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("X-Hibou-Pod-UID", w.podUID)
	req.Header.Set("Content-Type", "application/json")
	res, err := w.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, invalidStatus(res.StatusCode)
	}
	return readBounded(res.Body, MaxBodyBytes)
}
func (w *WorkerTransport) Input(ctx context.Context) ([]byte, error) {
	return w.request(ctx, "GET", "/input", nil)
}
func (w *WorkerTransport) Output(ctx context.Context, data []byte) error {
	_, err := w.request(ctx, "POST", "/output", data)
	return err
}

// Do forwards a relative path to the per-attempt delegated domain handler.
func (w *WorkerTransport) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\") || strings.Contains(path, "..") || strings.Contains(path, "%") || len(path) > 1024 {
		return nil, errors.New("invalid scoped broker path")
	}
	if method != "GET" && method != "POST" {
		return nil, errors.New("unsupported scoped broker method")
	}
	return w.request(ctx, method, "/proxy"+path, body)
}

// ProxyURL is the base URL for a domain RegistryClient. The delegated handler
// sees /match or /registry/... with /v1/workloads/{attempt}/proxy stripped.
func (w *WorkerTransport) ProxyURL() string { return w.base + "/proxy" }

// HTTPClient supports bounded streaming (e.g. registry archives), injects the
// capability only for this attempt's proxy, and never follows redirects.
func (w *WorkerTransport) HTTPClient() *http.Client {
	return &http.Client{Timeout: w.http.Timeout, Transport: w, CheckRedirect: w.http.CheckRedirect}
}

// RoundTrip implements http.RoundTripper for this attempt's delegated proxy
// only. Use HTTPClient to retain the mandatory redirect-denial policy.
func (w *WorkerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("workload proxy request required")
	}
	prefix := w.ProxyURL() + "/"
	if req.URL == nil || !strings.HasPrefix(req.URL.String(), prefix) || req.URL.RawQuery != "" || req.URL.Fragment != "" || req.URL.User != nil ||
		(req.Method != http.MethodGet && req.Method != http.MethodPost) || req.ContentLength > MaxBodyBytes {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errors.New("request outside delegated workload scope")
	}
	copy := req.Clone(req.Context())
	copy.Header = req.Header.Clone()
	copy.Header.Set("Authorization", "Bearer "+w.token)
	copy.Header.Set("X-Hibou-Pod-UID", w.podUID)
	if copy.Body != nil {
		copy.Body = &boundedReadCloser{ReadCloser: copy.Body, remaining: MaxBodyBytes}
	}
	res, err := w.http.Transport.RoundTrip(copy)
	if err != nil {
		return nil, err
	}
	if res.ContentLength > MaxBodyBytes {
		res.Body.Close()
		return nil, errors.New("worker response exceeds limit")
	}
	res.Body = &boundedReadCloser{ReadCloser: res.Body, remaining: MaxBodyBytes}
	return res, nil
}

type boundedReadCloser struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedReadCloser) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.ReadCloser.Read(extra[:])
		if n > 0 {
			return 0, errors.New("worker stream exceeds limit")
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
