package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type APIConfig struct{ URL, TokenFile, CAFile string }
type Client struct {
	base, tokenFile string
	http            *http.Client
}

func NewClient(c APIConfig) (*Client, error) {
	u, err := secureURL(c.URL)
	if err != nil || u.Path != "" || c.TokenFile == "" {
		return nil, errors.New("invalid Kubernetes API configuration")
	}
	ca, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes CA: %w", err)
	}
	h, err := tlsClient(string(ca))
	if err != nil {
		return nil, err
	}
	return &Client{c.URL, c.TokenFile, h}, nil
}

func InClusterClient() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if host == "" || port == "" {
		return nil, errors.New("in-cluster Kubernetes HTTPS endpoint absent")
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return NewClient(APIConfig{"https://" + host + ":" + port, "/var/run/secrets/kubernetes.io/serviceaccount/token", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"})
}

type APIError struct{ Code int }

func (e *APIError) Error() string { return fmt.Sprintf("Kubernetes API returned HTTP %d", e.Code) }

// request deliberately reopens the projected token for each call so kubelet
// rotation is honored. Error response bodies are never surfaced (may contain
// credentials or repository-controlled strings).
func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return errors.New("read Kubernetes service account token")
	}
	t := strings.TrimSpace(string(token))
	if !boundedString(t, 16384) {
		return errors.New("invalid Kubernetes service account token")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request to Kubernetes API failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &APIError{res.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return errors.New("response from Kubernetes exceeds limit")
	}
	mediaType, _, mediaErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" || len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return errors.New("response from Kubernetes is not a JSON object")
	}
	var envelope struct {
		Kind   string
		Status json.RawMessage
		Code   int
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return errors.New("invalid Kubernetes JSON response")
	}
	if envelope.Kind == "Status" {
		var status string
		if json.Unmarshal(envelope.Status, &status) != nil || status != "Success" || (envelope.Code != 0 && (envelope.Code < 200 || envelope.Code >= 300)) {
			return errors.New("operation reported failure by Kubernetes")
		}
	}
	if out == nil {
		out = new(map[string]any)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(out); err != nil {
		return errors.New("invalid Kubernetes JSON response")
	}
	if !errors.Is(dec.Decode(new(any)), io.EOF) {
		return errors.New("trailing Kubernetes JSON response")
	}
	return nil
}

func (c *Client) version(ctx context.Context) error {
	var v struct{ Major, Minor string }
	if err := c.request(ctx, "GET", "/version", nil, &v); err != nil {
		return err
	}
	major, e1 := strconv.Atoi(v.Major)
	minor, e2 := strconv.Atoi(strings.TrimSuffix(v.Minor, "+"))
	if e1 != nil || e2 != nil || major != 1 || minor < 33 || minor > 36 {
		return errors.New("supported Kubernetes matrix is 1.33 through 1.36; user namespaces must be enabled")
	}
	return nil
}
func (c *Client) jobs(ns string) string {
	return "/apis/batch/v1/namespaces/" + url.PathEscape(ns) + "/jobs"
}
func (c *Client) pods(ns string) string { return "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods" }
func (c *Client) delete(ctx context.Context, ns, name, uid string) error {
	if uid == "" {
		return errors.New("refusing delete without Job UID")
	}
	err := c.request(ctx, "DELETE", c.jobs(ns)+"/"+url.PathEscape(name), map[string]any{
		"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground", "preconditions": map[string]string{"uid": uid},
	}, nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == 404 {
		return nil
	}
	return err
}
