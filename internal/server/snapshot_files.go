package server

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

// snapshotFileResponse is the API shape for one downloadable artifact.
type snapshotFileResponse struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Format      string `json:"format,omitempty"`
	ToolName    string `json:"tool_name,omitempty"`
	Filename    string `json:"filename"`
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	DownloadURL string `json:"download_url"`
	CreatedAt   string `json:"created_at"`
}

var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// loadAuthorizedSnapshotFiles resolves repo → snapshot (with ownership check)
// and lists its artifacts. Shared by the list/download/archive handlers.
func (s *Server) loadAuthorizedSnapshotFiles(w http.ResponseWriter, r *http.Request) (*store.Repository, *store.Snapshot, []store.SnapshotArtifact, bool) {
	_, repo, ok := s.loadAuthorizedRepo(r, w)
	if !ok {
		return nil, nil, nil, false
	}

	snapshot, status, message := s.loadSnapshotForRepoByID(r, repo, chi.URLParam(r, "snapshotID"))
	if status != 0 {
		api.JSONError(w, status, message)
		return nil, nil, nil, false
	}

	artifacts, err := s.queries.ListSnapshotArtifactsBySnapshot(r.Context(), snapshot.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list snapshot files")
		return nil, nil, nil, false
	}
	return repo, snapshot, artifacts, true
}

func (s *Server) handleListSnapshotFiles(w http.ResponseWriter, r *http.Request) {
	_, _, artifacts, ok := s.loadAuthorizedSnapshotFiles(w, r)
	if !ok {
		return
	}

	base := strings.TrimSuffix(r.URL.Path, "/files")
	used := make(map[string]int, len(artifacts))
	files := make([]snapshotFileResponse, 0, len(artifacts))
	for _, a := range artifacts {
		files = append(files, snapshotFileResponse{
			ID:          a.ID.String(),
			Kind:        a.Kind,
			Format:      derefString(a.Format),
			ToolName:    derefString(a.ToolName),
			Filename:    uniqueArtifactFilename(a, used),
			SizeBytes:   a.SizeBytes,
			SHA256:      derefString(a.SHA256),
			ContentType: derefString(a.ContentType),
			DownloadURL: fmt.Sprintf("%s/files/%s", base, a.ID),
			CreatedAt:   a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	api.JSON(w, http.StatusOK, files)
}

func (s *Server) handleDownloadSnapshotFile(w http.ResponseWriter, r *http.Request) {
	repo, _, artifacts, ok := s.loadAuthorizedSnapshotFiles(w, r)
	if !ok {
		return
	}
	if !s.requireRawArtifactAccess(w, r, repo) {
		return
	}

	artifactID := chi.URLParam(r, "artifactID")
	var match *store.SnapshotArtifact
	used := make(map[string]int, len(artifacts))
	var filename string
	for i := range artifacts {
		name := uniqueArtifactFilename(artifacts[i], used)
		if artifacts[i].ID.String() == artifactID {
			match = &artifacts[i]
			filename = name
		}
	}
	if match == nil {
		api.JSONError(w, http.StatusNotFound, "file not found")
		return
	}

	rc, err := s.objStore.Get(r.Context(), match.ObjectKey)
	if err != nil {
		// The blob may have been garbage-collected; treat as missing, not 500.
		api.JSONError(w, http.StatusNotFound, "file is no longer available")
		return
	}
	defer func() { _ = rc.Close() }()

	contentType := derefString(match.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, filename))
	if match.SizeBytes > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(match.SizeBytes, 10))
	}
	_, _ = io.Copy(w, rc)
}

func (s *Server) handleDownloadSnapshotArchive(w http.ResponseWriter, r *http.Request) {
	repo, snapshot, artifacts, ok := s.loadAuthorizedSnapshotFiles(w, r)
	if !ok {
		return
	}
	if !s.requireRawArtifactAccess(w, r, repo) {
		return
	}
	if len(artifacts) == 0 {
		api.JSONError(w, http.StatusNotFound, "snapshot has no files")
		return
	}

	archiveName := fmt.Sprintf("hibou-snapshot-%s.zip", shortID(snapshot.ID.String()))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, archiveName))

	zw := zip.NewWriter(w)
	defer func() { _ = zw.Close() }()

	used := make(map[string]int, len(artifacts))
	for i := range artifacts {
		name := uniqueArtifactFilename(artifacts[i], used)
		rc, err := s.objStore.Get(r.Context(), artifacts[i].ObjectKey)
		if err != nil {
			// Skip blobs that are gone rather than aborting the whole archive.
			continue
		}
		fw, err := zw.Create(name)
		if err != nil {
			_ = rc.Close()
			return
		}
		_, _ = io.Copy(fw, rc)
		_ = rc.Close()
	}
}

// rawArtifactAccessMessage is the 403 body for a read-only role downloading
// raw uploads.
const rawArtifactAccessMessage = "downloading raw uploaded artifacts requires the developer role or higher on this repository"

// requireRawArtifactAccess limits raw artifact bytes to roles that can write
// the repository. Uploaded reports can carry more than the findings derived
// from them (source excerpts, scanner context, environment details), so
// viewer and auditor roles get the parsed findings, not the files.
func (s *Server) requireRawArtifactAccess(w http.ResponseWriter, r *http.Request, repo *store.Repository) bool {
	orgRole, err := s.principalOrgRole(r, repo.OrgID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return false
	}
	access, err := s.principalRepoAccess(r, repo.OrgID, orgRole)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
		return false
	}
	if !roleCanWrite(access.repoRole(orgRole, repo.ID)) {
		api.JSONError(w, http.StatusForbidden, rawArtifactAccessMessage)
		return false
	}
	return true
}

// uniqueArtifactFilename derives a stable download name from the artifact's
// kind/format/tool (the original upload filename is not persisted) and ensures
// uniqueness within a listing by appending a numeric suffix on collision.
func uniqueArtifactFilename(a store.SnapshotArtifact, used map[string]int) string {
	name := artifactFilename(a)
	if n, seen := used[name]; seen {
		used[name] = n + 1
		ext := path.Ext(name)
		stem := strings.TrimSuffix(name, ext)
		return fmt.Sprintf("%s-%d%s", stem, n, ext)
	}
	used[name] = 1
	return name
}

func artifactFilename(a store.SnapshotArtifact) string {
	// Prefer the original uploaded name when it was persisted; older rows and
	// server-side artifacts fall back to a name derived from kind/format/tool.
	if name := strings.TrimSpace(a.Filename); name != "" {
		return strings.Trim(unsafeFilenameChars.ReplaceAllString(path.Base(name), "-"), "-")
	}
	stem := a.Kind
	if tool := strings.TrimSpace(derefString(a.ToolName)); tool != "" {
		stem = tool
	}
	stem = strings.Trim(unsafeFilenameChars.ReplaceAllString(stem, "-"), "-")
	if stem == "" {
		stem = "artifact"
	}
	return stem + artifactExt(a.Kind, derefString(a.Format))
}

func artifactExt(kind, format string) string {
	switch strings.ToLower(kind) {
	case "sarif":
		return ".sarif"
	case "sbom":
		switch strings.ToLower(format) {
		case "cyclonedx", "cyclonedx-json":
			return ".cdx.json"
		case "spdx", "spdx-json":
			return ".spdx.json"
		default:
			return ".json"
		}
	case "junit", "test", "tests":
		return ".xml"
	case "coverage":
		switch strings.ToLower(format) {
		case "lcov":
			return ".lcov"
		case "go", "gocover":
			return ".out"
		default:
			return ".txt"
		}
	case "vex":
		return ".json"
	default:
		return ".bin"
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func shortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}
