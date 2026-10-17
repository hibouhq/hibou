package depinventory

import (
	"context"
	"crypto/sha1" // #nosec G505 -- Maven Central indexes artifacts by SHA-1; this is a lookup key, not a security hash
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/osv-scalibr/purl"
)

// Jars without Maven metadata (ADR-046 §4.2): a jar that lost its
// pom.properties (shaded, repackaged, copied from a build without the
// Maven plugin) can still be identified by the SHA-1 of its bytes, which
// Maven Central indexes. This sends a hash of the file out, so it is an
// opt-in the user makes per scan, never a default.

// JarLookup identifies a jar by the SHA-1 of its bytes. It returns ok
// false when the index does not know the hash.
type JarLookup func(ctx context.Context, sha1Hex string) (groupID, artifactID, version string, ok bool, err error)

// DefaultMavenCentralURL is the public search API.
const DefaultMavenCentralURL = "https://search.maven.org"

// ExtractorMavenCentral names the lookup as a component's extractor.
const ExtractorMavenCentral = "mavencentral"

// MavenCentralLookup asks the Maven Central search API (or a mirror of
// it at baseURL) for the coordinates of a SHA-1.
func MavenCentralLookup(baseURL string, client *http.Client) JarLookup {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultMavenCentralURL
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return func(ctx context.Context, sha1Hex string) (string, string, string, bool, error) {
		query := url.Values{}
		query.Set("q", `1:"`+sha1Hex+`"`)
		query.Set("rows", "1")
		query.Set("wt", "json")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/solrsearch/select?"+query.Encode(), nil)
		if err != nil {
			return "", "", "", false, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", "", "", false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", "", "", false, fmt.Errorf("maven central: HTTP %d", resp.StatusCode)
		}
		var body struct {
			Response struct {
				NumFound int `json:"numFound"`
				Docs     []struct {
					G string `json:"g"`
					A string `json:"a"`
					V string `json:"v"`
				} `json:"docs"`
			} `json:"response"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return "", "", "", false, fmt.Errorf("maven central: %w", err)
		}
		if body.Response.NumFound == 0 || len(body.Response.Docs) == 0 {
			return "", "", "", false, nil
		}
		doc := body.Response.Docs[0]
		if doc.G == "" || doc.A == "" || doc.V == "" {
			return "", "", "", false, nil
		}
		return doc.G, doc.A, doc.V, true, nil
	}
}

// identifyJars tries the lookup on every unidentified jar and returns the
// components it yielded with the entries still unidentified. A lookup
// error is reported once and stops further lookups for this scan.
func identifyJars(ctx context.Context, fsys fs.FS, unidentified []Unidentified, opts ScanOptions) ([]Component, []Unidentified) {
	var found []Component
	rest := make([]Unidentified, 0, len(unidentified))
	failed := false
	for _, entry := range unidentified {
		if failed || entry.Type != "java archive without Maven metadata" {
			rest = append(rest, entry)
			continue
		}
		digest, err := sha1OfFile(fsys, entry.Path)
		if err != nil {
			rest = append(rest, entry)
			continue
		}
		groupID, artifactID, version, ok, err := opts.JarLookup(ctx, digest)
		if err != nil {
			opts.Warn(fmt.Sprintf("jar lookup failed, remaining jars stay unidentified: %v", err))
			failed = true
			rest = append(rest, entry)
			continue
		}
		if !ok {
			rest = append(rest, entry)
			continue
		}
		found = append(found, Component{
			Purl:         purl.PackageURL{Type: purl.TypeMaven, Namespace: groupID, Name: artifactID, Version: version}.String(),
			Name:         groupID + ":" + artifactID,
			Version:      version,
			Ecosystem:    "maven",
			Relationship: RelationshipUnknown,
			Resolution:   ResolutionArtifact,
			Path:         entry.Path,
			Module:       moduleOf(entry.Path),
			Extractor:    ExtractorMavenCentral,
		})
	}
	return found, rest
}

func sha1OfFile(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha1.New() // #nosec G401 -- lookup key for the Maven Central index
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
