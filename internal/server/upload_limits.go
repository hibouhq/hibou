package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/auth"
)

// defaultUploadMaxItems applies when a Server is built without config.Load.
const defaultUploadMaxItems = 200000

func (s *Server) uploadMaxItems() int {
	if s.limits.Upload.MaxItems > 0 {
		return s.limits.Upload.MaxItems
	}
	return defaultUploadMaxItems
}

// skipJSON consumes a JSON value without keeping it: a []skipJSON costs no
// memory per element, so counting a document's entries does not copy it.
type skipJSON struct{}

func (*skipJSON) UnmarshalJSON([]byte) error { return nil }

// uploadJSONProbe reads only what type detection and the item cap need. It
// replaces a map[string]json.RawMessage probe that copied the whole document
// (every top-level value) once more per upload.
type uploadJSONProbe struct {
	Context     json.RawMessage `json:"@context"`
	Statements  []skipJSON      `json:"statements"`
	BOMFormat   json.RawMessage `json:"bomFormat"`
	SPDXVersion json.RawMessage `json:"spdxVersion"`
	Components  []skipJSON      `json:"components"`
	Packages    []skipJSON      `json:"packages"`
	Schema      json.RawMessage `json:"$schema"`
	Document    struct {
		Category string `json:"category"`
	} `json:"document"`
	Vulnerabilities []skipJSON `json:"vulnerabilities"`
	Runs            []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		Results []skipJSON `json:"results"`
	} `json:"runs"`
}

// detect mirrors detectJSONArtifactType's precedence.
func (p *uploadJSONProbe) detect() (string, string, string, int, bool) {
	var context string
	if json.Unmarshal(p.Context, &context) == nil && strings.Contains(context, "openvex.dev") {
		return "vex", "openvex", "", len(p.Statements), true
	}
	if p.Document.Category == "csaf_vex" {
		return "vex", "csaf", "", len(p.Vulnerabilities), true
	}
	if p.BOMFormat != nil {
		return "sbom", "cyclonedx-json", "", len(p.Components), true
	}
	if p.SPDXVersion != nil {
		return "sbom", "spdx-json", "", len(p.Packages), true
	}
	var schema string
	if p.Runs != nil || (json.Unmarshal(p.Schema, &schema) == nil && strings.Contains(strings.ToLower(schema), "sarif")) {
		tool := ""
		results := 0
		for index, run := range p.Runs {
			if index == 0 {
				tool = strings.ToLower(strings.TrimSpace(run.Tool.Driver.Name))
			}
			results += len(run.Results)
		}
		return "sarif", "", tool, results, true
	}
	return "", "", "", 0, false
}

// detectArtifactTypeAndCount is detectArtifactType plus the number of entries
// the artifact will expand into (SARIF results, SBOM components or packages,
// VEX statements, test cases), checked against upload.max_items before any
// processing. A document the narrow probe cannot read falls back to the
// general detector, uncounted.
func detectArtifactTypeAndCount(content []byte) (string, string, string, int, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var probe uploadJSONProbe
		if json.Unmarshal(trimmed, &probe) == nil {
			if uploadType, format, tool, items, ok := probe.detect(); ok {
				return uploadType, format, tool, items, nil
			}
		}
	}
	uploadType, format, tool, err := detectArtifactType(content)
	if err != nil {
		return "", "", "", 0, err
	}
	return uploadType, format, tool, countTextArtifactItems(format, trimmed), nil
}

// countTextArtifactItems approximates the entry count of XML and tag-value
// formats by their element markers; a slight overcount is harmless for a cap.
func countTextArtifactItems(format string, content []byte) int {
	var marker string
	switch format {
	case "cyclonedx-xml":
		marker = "<component"
	case "spdx-xml":
		marker = "<spdx:Package"
	case "spdx-tv":
		marker = "PackageName:"
	case "junit":
		marker = "<testcase"
	default:
		return 0
	}
	return bytes.Count(content, []byte(marker))
}

// uploadAdmission is what an upload must pass before it may queue for a
// slot. The target org and repository are in the body, which is exactly what
// a slot protects, so the full check stays in the handler; here the caller
// must be a principal that can upload somewhere: a token whose scope grants
// uploads:write, and a user who belongs to at least one organization. It
// returns the in-flight keys the upload counts against: the user (whatever
// token they use) or the service token, plus the org of a service token.
func (s *Server) uploadAdmission(w http.ResponseWriter, r *http.Request) ([]inFlightKey, bool) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapUploads, apitoken.AccessWrite, "", "") {
		return nil, false
	}
	perPrincipal := s.limits.Upload.MaxConcurrentPerPrincipal
	if tokenAuth := auth.TokenAuthFromContext(r.Context()); tokenAuth.IsServicePrincipal() {
		return []inFlightKey{
			{key: "key:" + tokenAuth.KeyID.String(), limit: perPrincipal},
			{key: "org:" + tokenAuth.OwnerID.String(), limit: s.limits.Upload.MaxConcurrentPerOrg},
		}, true
	}
	user := UserFromContext(r.Context())
	orgs, _, err := s.queries.ListOrganizationsByUser(r.Context(), user.ID, 1, 0)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to check organization membership")
		return nil, false
	}
	if len(orgs) == 0 {
		api.JSONError(w, http.StatusForbidden, "uploading requires membership of an organization")
		return nil, false
	}
	return []inFlightKey{{key: "user:" + user.ID.String(), limit: perPrincipal}}, true
}

// errUploadTooSlow fails the body read of an upload that stalled or trickled
// below upload.min_throughput_bytes per upload.min_throughput_window.
var errUploadTooSlow = errors.New("upload body arrived too slowly (upload.min_throughput_bytes per upload.min_throughput_window)")

// uploadThroughputGuard wraps an upload body while it holds a slot. Every
// window it checks the bytes read since the last check; when a read is
// pending and fewer than minBytes arrived, it expires the connection's read
// deadline, so a body that stalls or trickles fails instead of holding the
// slot for the whole http.upload_read_timeout. A handler busy processing
// (no read pending) is never cut off.
type uploadThroughputGuard struct {
	body    io.ReadCloser
	read    atomic.Int64
	pending atomic.Bool
	tooSlow atomic.Bool
	done    chan struct{}
	once    sync.Once
}

func newUploadThroughputGuard(w http.ResponseWriter, body io.ReadCloser, minBytes int64, window time.Duration) *uploadThroughputGuard {
	guard := &uploadThroughputGuard{body: body, done: make(chan struct{})}
	if body == nil || body == http.NoBody || minBytes <= 0 || window <= 0 {
		return guard
	}
	controller := http.NewResponseController(w)
	go guard.watch(controller, minBytes, window)
	return guard
}

func (g *uploadThroughputGuard) watch(controller *http.ResponseController, minBytes int64, window time.Duration) {
	ticker := time.NewTicker(window)
	defer ticker.Stop()
	var last int64
	for {
		select {
		case <-g.done:
			return
		case <-ticker.C:
			read := g.read.Load()
			if g.pending.Load() && read-last < minBytes {
				g.tooSlow.Store(true)
				// Unblocks the pending Read with a timeout error.
				_ = controller.SetReadDeadline(time.Now())
				return
			}
			last = read
		}
	}
}

func (g *uploadThroughputGuard) Read(p []byte) (int, error) {
	if g.tooSlow.Load() {
		return 0, errUploadTooSlow
	}
	g.pending.Store(true)
	n, err := g.body.Read(p)
	g.pending.Store(false)
	g.read.Add(int64(n))
	if err != nil && g.tooSlow.Load() {
		return n, errUploadTooSlow
	}
	if err == io.EOF {
		g.stop()
	}
	return n, err
}

func (g *uploadThroughputGuard) Close() error {
	g.stop()
	if g.body == nil {
		return nil
	}
	return g.body.Close()
}

// stop ends the watchdog; idempotent.
func (g *uploadThroughputGuard) stop() {
	g.once.Do(func() { close(g.done) })
}
