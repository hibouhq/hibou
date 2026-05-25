package cliclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/lehibou/internal/cliconfig"
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

// NewWithOverrides creates a client from flag/env/config values.
func NewWithOverrides(serverOverride, tokenOverride string) (*Client, error) {
	cfg, err := cliconfig.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	server := strings.TrimSpace(serverOverride)
	if server == "" {
		server = strings.TrimSpace(cfg.Server)
	}
	if server == "" {
		return nil, errors.New("not logged in — run 'hibou login' first")
	}

	token := strings.TrimSpace(tokenOverride)
	if token == "" {
		token = strings.TrimSpace(cfg.Token)
	}
	if token == "" {
		return nil, errors.New("no token configured — run 'hibou login' first")
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

func (c *Client) do(method, path string, body any, out any) error {
	url := c.Server + "/api/v1" + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
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

	return c.doRequest(req, out)
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
		var apiResp APIResponse
		if json.Unmarshal(respBody, &apiResp) == nil && apiResp.Error != "" {
			return fmt.Errorf("API error (%d): %s", resp.StatusCode, apiResp.Error)
		}
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
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
