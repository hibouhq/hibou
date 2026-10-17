package forge

import (
	"io"
	"net"
	"net/http"
	"time"
)

// Forge API calls run in background jobs (membership re-validation, late
// repositories, sign-in sync) as well as requests. Without deadlines, one
// response that never arrives stops the job silently; without a size cap,
// one huge response exhausts memory.
const (
	// HTTPTimeout bounds a whole request, body included.
	HTTPTimeout = 60 * time.Second
	// MaxResponseBytes caps a forge JSON response. The largest legitimate
	// ones (recursive tree listings at the API's own truncation limit) are
	// a few tens of MB.
	MaxResponseBytes = 64 << 20
)

// NewHTTPClient returns the client forge providers use: connect, TLS
// handshake and response header deadlines, and an overall timeout.
func NewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.ExpectContinueTimeout = time.Second
	return &http.Client{Timeout: HTTPTimeout, Transport: transport}
}

// LimitResponse caps a response body at MaxResponseBytes; reading past it
// fails instead of growing without bound.
func LimitResponse(body io.Reader) io.Reader {
	return &limitedResponse{r: io.LimitReader(body, MaxResponseBytes+1)}
}

type limitedResponse struct {
	r    io.Reader
	read int64
}

func (l *limitedResponse) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.read += int64(n)
	if l.read > MaxResponseBytes {
		return n, errResponseTooLarge
	}
	return n, err
}

var errResponseTooLarge = &responseTooLargeError{}

type responseTooLargeError struct{}

func (*responseTooLargeError) Error() string {
	return "forge response exceeds the size limit"
}
