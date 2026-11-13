package remediation

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type NPMMirrorConfig struct {
	URL       string
	CAFile    string
	TokenFile string
}

// NewNPMMirrorClient preserves npm identities while acquiring metadata/archives
// only from one operator-approved HTTPS mirror. It has no public fallback.
func NewNPMMirrorClient(cfg NPMMirrorConfig) (*http.Client, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || base.Hostname() == "registry.npmjs.org" ||
		path.Clean(base.Path) != strings.TrimSuffix(base.Path, "/") && base.Path != "" && base.Path != "/" {
		return nil, errors.New("an approved HTTPS npm mirror origin/path is required")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if cfg.CAFile != "" {
		ca, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(ca) {
			return nil, errors.New("npm mirror CA bundle contains no certificates")
		}
	}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ResponseHeaderTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 4,
	}
	return &http.Client{
		Transport: &npmMirrorTransport{base: base, tokenFile: cfg.TokenFile, transport: transport},
		Timeout:   45 * time.Second, CheckRedirect: refuseJobRedirect,
	}, nil
}

type npmMirrorTransport struct {
	base      *url.URL
	tokenFile string
	transport http.RoundTripper
}

func (t *npmMirrorTransport) CloseIdleConnections() {
	if transport, ok := t.transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

func (t *npmMirrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != "registry.npmjs.org" || req.URL.User != nil ||
		(req.Method != http.MethodGet && req.Method != http.MethodHead) {
		return nil, errors.New("only canonical read-only npm identities may use the mirror")
	}
	clone := req.Clone(req.Context())
	target := *t.base
	target.Path = strings.TrimSuffix(target.Path, "/") + req.URL.Path
	target.RawQuery = req.URL.RawQuery
	target.RawPath = ""
	clone.URL, clone.Host = &target, target.Host
	clone.Header = make(http.Header)
	clone.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	if t.tokenFile != "" {
		token, err := os.ReadFile(t.tokenFile)
		if err != nil {
			return nil, err
		}
		value := strings.TrimSpace(string(token))
		if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("invalid npm mirror bearer credential")
		}
		clone.Header.Set("Authorization", "Bearer "+value)
	}
	resp, err := t.transport.RoundTrip(clone)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || req.Method == http.MethodHead || strings.Contains(req.URL.Path, "/-/") {
		return resp, nil
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxFileBytes+1))
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > MaxFileBytes {
		return nil, errors.New("npm mirror metadata exceeds the profile limit")
	}
	data, err = normalizeMirrorMetadata(data, t.base)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.ContentLength = int64(len(data))
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
	return resp, nil
}

func normalizeMirrorMetadata(data []byte, base *url.URL) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if raw, ok := doc["versions"]; ok {
		var versions map[string]json.RawMessage
		if err := json.Unmarshal(raw, &versions); err != nil {
			return nil, err
		}
		for version, entry := range versions {
			normalized, err := normalizeMirrorMetadata(entry, base)
			if err != nil {
				return nil, err
			}
			versions[version] = normalized
		}
		encoded, err := json.Marshal(versions)
		if err != nil {
			return nil, err
		}
		doc["versions"] = encoded
	}
	if raw, ok := doc["dist"]; ok {
		var dist map[string]json.RawMessage
		if err := json.Unmarshal(raw, &dist); err != nil {
			return nil, err
		}
		if encoded, ok := dist["tarball"]; ok {
			var location string
			if err := json.Unmarshal(encoded, &location); err != nil {
				return nil, err
			}
			u, err := url.Parse(location)
			if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return nil, errors.New("invalid npm mirror archive location")
			}
			prefix := strings.TrimSuffix(base.Path, "/") + "/"
			switch {
			case u.Scheme == "https" && u.Host == base.Host && strings.HasPrefix(u.Path, prefix):
				u.Scheme, u.Host = "https", "registry.npmjs.org"
				u.Path, u.RawPath = "/"+strings.TrimPrefix(u.Path, prefix), ""
			case u.Host == "registry.npmjs.org" && (u.Scheme == "http" || u.Scheme == "https"):
				u.Scheme = "https"
			default:
				return nil, errors.New("npm mirror returned an archive outside the approved origin/path")
			}
			dist["tarball"], err = json.Marshal(u.String())
			if err != nil {
				return nil, err
			}
		}
		encoded, err := json.Marshal(dist)
		if err != nil {
			return nil, err
		}
		doc["dist"] = encoded
	}
	return json.Marshal(doc)
}
