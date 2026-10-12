package cliclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/cliconfig"
)

// Client is a thin HTTP client for CLI commands.
type Client struct {
	Server     string
	Token      string
	HTTPClient *http.Client
}

// New creates a client from the stored config.
func New() (*Client, error) {
	return NewWithOverrides("", "")
}

// NewWithOverrides creates a client from flag/env/config values. Precedence:
// explicit override, then HIBOU_SERVER / HIBOU_TOKEN (the same variables the
// upload command reads, so pipelines configure the CLI once), then the stored
// login config.
func NewWithOverrides(serverOverride, tokenOverride string) (*Client, error) {
	cfg, err := cliconfig.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	server := strings.TrimSpace(serverOverride)
	if server == "" {
		server = strings.TrimSpace(os.Getenv("HIBOU_SERVER"))
	}
	if server == "" {
		server = strings.TrimSpace(cfg.Server)
	}
	if server == "" {
		return nil, errors.New("no server configured — run 'hibou login' or set HIBOU_SERVER")
	}

	token := strings.TrimSpace(tokenOverride)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("HIBOU_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(cfg.Token)
	}
	if token == "" {
		return nil, errors.New("no token configured — run 'hibou login' or set HIBOU_TOKEN")
	}

	return &Client{
		Server: strings.TrimRight(server, "/"),
		Token:  token,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// APIResponse is the standard envelope from the Hibou API.
type APIResponse struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
	Meta  json.RawMessage `json:"meta,omitempty"`
}

// Get performs an authenticated GET request and decodes the response.
func (c *Client) Get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

// Post performs an authenticated POST request with a JSON body.
func (c *Client) Post(path string, body any, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

// PostRaw performs an authenticated POST request with a raw reader body.
func (c *Client) PostRaw(path string, contentType string, body io.Reader, out any) error {
	url := c.Server + "/api/v1" + path
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", contentType)

	return c.doRequest(req, out)
}

// maxRetryAttempts bounds retries of a request the server shed with 429/503
// (rate limit, upload concurrency limit). Each wait honours Retry-After.
const maxRetryAttempts = 4

// retrySleep is swapped by tests.
var retrySleep = time.Sleep

func (c *Client) do(method, path string, body any, out any) error {
	url := c.Server + "/api/v1" + path

	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
	}

	for attempt := 1; ; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(data)
		}
		req, err := http.NewRequest(method, url, bodyReader)
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", "Bearer "+c.Token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		err = c.doRequest(req, out)
		var shed *shedError
		if !errors.As(err, &shed) || attempt >= maxRetryAttempts {
			return err
		}
		fmt.Fprintf(os.Stderr, "server busy (%d), retrying in %s\n", shed.status, shed.wait)
		retrySleep(shed.wait)
	}
}

// shedError is a 429/503 the server asked the client to retry later.
type shedError struct {
	status int
	wait   time.Duration
	err    error
}

func (e *shedError) Error() string { return e.err.Error() }
func (e *shedError) Unwrap() error { return e.err }

// retryAfter reads a Retry-After seconds value, bounded so a misbehaving
// server cannot park a CI job.
func retryAfter(header string) time.Duration {
	const fallback, ceiling = 5 * time.Second, 60 * time.Second
	seconds, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || seconds <= 0 {
		return fallback
	}
	if wait := time.Duration(seconds) * time.Second; wait < ceiling {
		return wait
	}
	return ceiling
}

func (c *Client) doRequest(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr error
		var apiResp APIResponse
		if json.Unmarshal(respBody, &apiResp) == nil && apiResp.Error != "" {
			apiErr = fmt.Errorf("API error (%d): %s", resp.StatusCode, apiResp.Error)
		} else {
			apiErr = fmt.Errorf("API error (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			return &shedError{status: resp.StatusCode, wait: retryAfter(resp.Header.Get("Retry-After")), err: apiErr}
		}
		return apiErr
	}

	if out == nil {
		return nil
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if apiResp.Error != "" {
		return fmt.Errorf("API error: %s", apiResp.Error)
	}
	if apiResp.Data != nil {
		return json.Unmarshal(apiResp.Data, out)
	}

	return json.Unmarshal(respBody, out)
}
