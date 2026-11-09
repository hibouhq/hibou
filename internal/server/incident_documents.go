package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	textTemplate "text/template"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
	"github.com/hibouhq/hibou/internal/vex"
)

// Incident documents (ADR-053 §5). A document is rendered from recorded
// inputs by a deterministic renderer, stored under its SHA-256, and never
// changed. `verify` re-renders from the inputs and compares: recomputation
// verifies the evidence, it does not replace keeping the bytes.

// incidentDocumentRenderer names the renderer contract; it changes whenever
// identical inputs would render different bytes.
const incidentDocumentRenderer = "hibou-incident-documents/1+" + vex.RendererVersion

// Document kinds of a client document set.
const (
	docCSAFAdvisory = "csaf_advisory"
	docOpenVEX      = "openvex"
	docCycloneDX    = "cyclonedx_vex"
	docNoticeHTML   = "notice_html"
	docNoticeText   = "notice_text"
)

var clientDocumentKinds = []string{docCSAFAdvisory, docOpenVEX, docCycloneDX, docNoticeHTML, docNoticeText}

// documentMeta is the rendering metadata, recorded with the inputs.
type documentMeta struct {
	Author             string               `json:"author"`
	PublisherCategory  string               `json:"publisher_category"`
	PublisherName      string               `json:"publisher_name"`
	PublisherNamespace string               `json:"publisher_namespace"`
	DocumentID         string               `json:"document_id"`
	TrackingID         string               `json:"tracking_id"`
	TLP                string               `json:"tlp"`
	Title              string               `json:"title"`
	Timestamp          time.Time            `json:"timestamp"`
	InitialTimestamp   time.Time            `json:"initial_timestamp"`
	Version            int                  `json:"version"`
	Revisions          []vex.ExportRevision `json:"revisions,omitempty"`
}

func (m documentMeta) export() vex.ExportMeta {
	return vex.ExportMeta{
		Author:           m.Author,
		Publisher:        vex.ExportPublisher{Category: m.PublisherCategory, Name: m.PublisherName, Namespace: m.PublisherNamespace},
		DocumentID:       m.DocumentID,
		TrackingID:       m.TrackingID,
		TLPLabel:         m.TLP,
		Timestamp:        m.Timestamp,
		InitialTimestamp: m.InitialTimestamp,
		Version:          m.Version,
		Revisions:        m.Revisions,
		Title:            m.Title,
	}
}

// noticeRow is one version line of the human-readable notice.
type noticeRow struct {
	Version string `json:"version"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
}

type noticeInputs struct {
	Organisation   string      `json:"organisation"`
	Client         string      `json:"client"`
	IncidentNumber int32       `json:"incident_number"`
	Title          string      `json:"title"`
	Kind           string      `json:"kind"`
	Product        string      `json:"product"`
	Identifier     string      `json:"identifier"`
	Description    string      `json:"description,omitempty"`
	Exploitation   string      `json:"exploitation,omitempty"`
	Measures       string      `json:"measures,omitempty"`
	Rows           []noticeRow `json:"rows"`
	Contact        string      `json:"contact,omitempty"`
	Issued         time.Time   `json:"issued"`
	Version        int         `json:"version"`
}

// documentInputs is everything a document is rendered from.
type documentInputs struct {
	Renderer   string             `json:"renderer"`
	Kind       string             `json:"kind"`
	Meta       documentMeta       `json:"meta"`
	Statements []vex.Statement    `json:"statements,omitempty"`
	Advisories []vex.AdvisoryInfo `json:"advisories,omitempty"`
	Notice     *noticeInputs      `json:"notice,omitempty"`
}

// documentRef is a stored document as a delivery lists it.
type documentRef struct {
	Kind        string `json:"kind"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
}

// renderIncidentDocument renders inputs into bytes; same inputs, same bytes.
func renderIncidentDocument(in documentInputs) ([]byte, string, string, error) {
	base := strings.ToLower(in.Meta.TrackingID)
	if base == "" {
		base = "incident"
	}
	suffix := "-v" + strconv.Itoa(max(in.Meta.Version, 1))
	switch in.Kind {
	case docCSAFAdvisory:
		body, err := vex.ExportCSAFAdvisory(in.Statements, in.Meta.export(), in.Advisories)
		return body, "application/json", base + suffix + ".csaf.json", err
	case docOpenVEX:
		body, err := vex.ExportOpenVEX(in.Statements, in.Meta.export())
		return body, "application/json", base + suffix + ".openvex.json", err
	case docCycloneDX:
		body, err := vex.ExportCycloneDX(in.Statements, in.Meta.export())
		return body, "application/vnd.cyclonedx+json", base + suffix + ".cdx.json", err
	case docNoticeHTML:
		if in.Notice == nil {
			return nil, "", "", errors.New("notice inputs missing")
		}
		var buf bytes.Buffer
		if err := noticeHTMLTemplate.Execute(&buf, in.Notice); err != nil {
			return nil, "", "", err
		}
		return buf.Bytes(), "text/html; charset=utf-8", base + suffix + ".html", nil
	case docNoticeText:
		if in.Notice == nil {
			return nil, "", "", errors.New("notice inputs missing")
		}
		var buf bytes.Buffer
		if err := noticeTextTemplate.Execute(&buf, in.Notice); err != nil {
			return nil, "", "", err
		}
		return buf.Bytes(), "text/plain; charset=utf-8", base + suffix + ".txt", nil
	}
	return nil, "", "", fmt.Errorf("unknown document kind %q", in.Kind)
}

var noticeFuncs = map[string]any{
	"date": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
}

var noticeTextTemplate = textTemplate.Must(textTemplate.New("notice").Funcs(noticeFuncs).Parse(`Security notice from {{.Organisation}} to {{.Client}}
{{.Title}}
Reference: incident #{{.IncidentNumber}}, notice version {{.Version}}, issued {{date .Issued}}

Product: {{.Product}}
Vulnerability: {{.Identifier}}
{{if .Description}}
{{.Description}}
{{end}}{{if .Exploitation}}
Exploitation: {{.Exploitation}}
{{end}}
Your versions:
{{range .Rows}}  - {{.Version}}: {{.Status}}{{if .Detail}} — {{.Detail}}{{end}}
{{end}}{{if .Measures}}
What to do:
{{.Measures}}
{{end}}
The machine-readable documents attached (CSAF, OpenVEX, CycloneDX) state the same, version by version.
{{if .Contact}}Questions: {{.Contact}}
{{end}}`))

var noticeHTMLTemplate = template.Must(template.New("notice").Funcs(noticeFuncs).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1f2328;line-height:1.5}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left}th{background:#f6f8fa}.meta{color:#57606a;font-size:.9rem}</style>
</head><body>
<p class="meta">Security notice from {{.Organisation}} to {{.Client}} · incident #{{.IncidentNumber}} · version {{.Version}} · {{date .Issued}}</p>
<h1>{{.Title}}</h1>
<p><strong>Product:</strong> {{.Product}}<br><strong>Vulnerability:</strong> {{.Identifier}}</p>
{{if .Description}}<p>{{.Description}}</p>{{end}}
{{if .Exploitation}}<p><strong>Exploitation:</strong> {{.Exploitation}}</p>{{end}}
<h2>Your versions</h2>
<table><thead><tr><th>Version</th><th>Status</th><th>Detail</th></tr></thead><tbody>
{{range .Rows}}<tr><td>{{.Version}}</td><td>{{.Status}}</td><td>{{.Detail}}</td></tr>
{{end}}</tbody></table>
{{if .Measures}}<h2>What to do</h2><p>{{.Measures}}</p>{{end}}
<p class="meta">The machine-readable documents attached (CSAF, OpenVEX, CycloneDX) state the same, version by version.{{if .Contact}} Questions: {{.Contact}}{{end}}</p>
</body></html>
`))

// storeIncidentDocument renders and stores one document, content-addressed.
func (s *Server) storeIncidentDocument(ctx context.Context, orgID uuid.UUID, in documentInputs) (documentRef, []byte, error) {
	in.Renderer = incidentDocumentRenderer
	body, contentType, filename, err := renderIncidentDocument(in)
	if err != nil {
		return documentRef{}, nil, err
	}
	digest := sha256.Sum256(body)
	sum := hex.EncodeToString(digest[:])
	inputs, err := json.Marshal(in)
	if err != nil {
		return documentRef{}, nil, err
	}
	key := "incident-documents/" + orgID.String() + "/" + sum
	params := dbgen.PutIncidentDocumentParams{
		Sha256: sum, OrgID: orgID, Kind: in.Kind, ContentType: contentType, SizeBytes: int64(len(body)),
		ObjectKey: key, Renderer: in.Renderer, Inputs: inputs,
	}
	if s.objStore != nil {
		if exists, err := s.objStore.Exists(ctx, key); err != nil || !exists {
			if err := s.objStore.Put(ctx, key, bytes.NewReader(body), contentType); err != nil {
				return documentRef{}, nil, fmt.Errorf("store document: %w", err)
			}
		}
	} else {
		params.Content = body
	}
	if _, err := s.queries.Incidents().PutIncidentDocument(ctx, params); err != nil {
		return documentRef{}, nil, err
	}
	return documentRef{Kind: in.Kind, Filename: filename, ContentType: contentType, SHA256: sum, Size: int64(len(body))}, body, nil
}

// loadIncidentDocument returns a stored document's bytes, checked against its
// digest.
func (s *Server) loadIncidentDocument(ctx context.Context, orgID uuid.UUID, sum string) (dbgen.IncidentDocument, []byte, error) {
	row, err := s.queries.Incidents().GetIncidentDocument(ctx, dbgen.GetIncidentDocumentParams{Sha256: sum, OrgID: orgID})
	if err != nil {
		return row, nil, err
	}
	body := row.Content
	if len(body) == 0 && s.objStore != nil {
		reader, err := s.objStore.Get(ctx, row.ObjectKey)
		if err != nil {
			return row, nil, err
		}
		defer func() { _ = reader.Close() }()
		body, err = io.ReadAll(io.LimitReader(reader, 64<<20))
		if err != nil {
			return row, nil, err
		}
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != sum {
		return row, nil, fmt.Errorf("stored document %s does not match its digest", sum)
	}
	return row, body, nil
}

// verifyIncidentDocument re-renders a document from its recorded inputs.
func (s *Server) verifyIncidentDocument(ctx context.Context, orgID uuid.UUID, sum string) (map[string]any, error) {
	row, body, err := s.loadIncidentDocument(ctx, orgID, sum)
	if err != nil {
		return map[string]any{"sha256": sum, "stored_matches_digest": false, "error": err.Error()}, nil
	}
	var in documentInputs
	if err := json.Unmarshal(row.Inputs, &in); err != nil {
		return nil, err
	}
	result := map[string]any{"sha256": sum, "kind": row.Kind, "stored_matches_digest": true, "renderer": row.Renderer, "current_renderer": incidentDocumentRenderer}
	if in.Renderer != incidentDocumentRenderer {
		result["rerendered_matches"] = false
		result["note"] = "rendered by an earlier renderer version; the stored bytes are the evidence"
		return result, nil
	}
	rerendered, _, _, err := renderIncidentDocument(in)
	if err != nil {
		result["rerendered_matches"] = false
		result["error"] = err.Error()
		return result, nil
	}
	result["rerendered_matches"] = bytes.Equal(rerendered, body)
	return result, nil
}

// clientDocumentSet builds the inputs of every document one client receives
// for an incident (§5): the CSAF advisory, OpenVEX and CycloneDX statements,
// and the human-readable notice, scoped to the releases the client runs.
func (s *Server) clientDocumentSet(ctx context.Context, inc dbgen.Incident, org *store.Organization, client dbgen.Client, measures string, now time.Time) ([]documentInputs, error) {
	db := s.queries.Incidents()
	var repo *store.Repository
	if inc.RepoID.Valid {
		var err error
		repo, err = s.queries.GetRepositoryByID(ctx, inc.RepoID.UUID)
		if err != nil || repo == nil {
			return nil, fmt.Errorf("load repository: %w", err)
		}
	}
	product := productIdentity{Name: org.Name, PURL: "pkg:generic/" + org.Slug + "/" + org.Slug}
	if repo != nil {
		product = s.repoProduct(ctx, org, repo)
	}

	scope, err := db.ListIncidentScope(ctx, inc.ID)
	if err != nil {
		return nil, err
	}
	releases := map[string]dbgen.ListReleasesWithClientsByRepoRow{}
	if repo != nil {
		rows, err := db.ListReleasesWithClientsByRepo(ctx, repo.ID)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			releases[row.ID.String()] = row
		}
	}
	clientOn := func(releaseID string) bool {
		row, ok := releases[releaseID]
		if !ok {
			return false
		}
		for _, id := range row.ClientIds {
			if id == client.ID {
				return true
			}
		}
		return false
	}

	identifier := fmt.Sprintf("%s-INC-%d", strings.ToUpper(org.Slug), inc.Number)
	var aliases []string
	advisoryInfo := vex.AdvisoryInfo{VulnerabilityID: identifier, Title: inc.Title}
	var statementFacts []incident.StatementFact
	var statementRows map[string]dbgen.VexStatement
	if inc.SubjectType == incident.SubjectAdvisory {
		if advisoryID, err := uuid.Parse(inc.SubjectID); err == nil {
			if advisories, err := s.queries.GetAdvisoriesByIDs(ctx, []uuid.UUID{advisoryID}); err == nil && len(advisories) == 1 {
				advisory := advisories[0]
				identifier = advisory.CanonicalID
				aliases = s.advisoryAliases(ctx, advisory.ID)
				advisoryInfo = vex.AdvisoryInfo{
					VulnerabilityID: identifier, Title: firstNonEmptyString(advisory.Title, inc.Title), Description: advisory.Description,
				}
				if advisory.CvssScore.Valid {
					if score, err := strconv.ParseFloat(advisory.CvssScore.String, 64); err == nil {
						advisoryInfo.CVSSScore = score
					}
				}
				advisoryInfo.CVSSVector = advisory.CvssVector
				if advisory.CvssVersion.Valid {
					// CSAF wants "3.1", the column stores "v3.1".
					advisoryInfo.CVSSVersion = strings.TrimPrefix(string(advisory.CvssVersion.CvssVersion), "v")
				}
			}
			if repo != nil {
				statements, err := s.queries.ListVEXStatementsForAdvisoryRepo(ctx, org.ID, advisoryID, repo.ID)
				if err != nil {
					return nil, err
				}
				statementRows = map[string]dbgen.VexStatement{}
				for _, statement := range statements {
					statementRows[statement.ID.String()] = statement
					fact := incident.StatementFact{ID: statement.ID.String(), Status: string(statement.Status), Repo: statement.RepoID.Valid, CreatedAt: statement.CreatedAt}
					if statement.ReleaseID.Valid {
						fact.ReleaseID = statement.ReleaseID.UUID.String()
					}
					if statement.VersionRange.Valid {
						fact.VersionRange = statement.VersionRange.String
					}
					if statement.ComponentPurl.Valid {
						fact.ComponentPURL = statement.ComponentPurl.String
					}
					if statement.Justification.Valid {
						fact.Justification = string(statement.Justification.VexJustification)
					}
					statementFacts = append(statementFacts, fact)
				}
			}
		}
	}
	if inc.State == dbgen.IncidentStateReportable || inc.DecidedState.IncidentState == dbgen.IncidentStateReportable {
		advisoryInfo.ExploitStatus = "Exploitation observed: reliable evidence that the vulnerability was exploited."
	}

	measures = strings.TrimSpace(measures)
	statements := []vex.Statement{}
	notice := noticeInputs{
		Organisation: firstNonEmptyString(org.DisplayName, org.Name), Client: client.Name, IncidentNumber: inc.Number,
		Title: inc.Title, Kind: incident.KindLabel(inc.Kind), Product: product.Name, Identifier: identifier,
		Description: advisoryInfo.Description, Exploitation: advisoryInfo.ExploitStatus, Measures: measures, Issued: now,
	}
	for _, row := range scope {
		if row.SubjectType != incident.ScopeRelease || !clientOn(row.SubjectID) {
			continue
		}
		status, detail := clientFacingStatus(row.Status)
		if status == "" {
			continue
		}
		statement := vex.Statement{
			VulnerabilityID: identifier, Aliases: aliases, Status: status,
			ComponentPURL: row.ComponentPurl, ProductPURL: product.PURL, ProductName: product.Name,
			ProductVersion: row.Label, ProductCPE: cpeForVersion(product.CPE, row.Label),
		}
		if release, ok := releases[row.SubjectID]; ok {
			fact := incident.ReleaseFact{ID: row.SubjectID, Version: release.Version, ComponentPURL: row.ComponentPurl}
			if chosen := incident.StatementFor(statementFacts, fact); chosen != nil {
				if stored, ok := statementRows[chosen.ID]; ok {
					statement.ImpactStatement = stored.ImpactStatement
					statement.ActionStatement = stored.ActionStatement
					if stored.Justification.Valid && status == vex.StatusNotAffected {
						statement.Justification = string(stored.Justification.VexJustification)
					}
				}
			}
		}
		if status == vex.StatusNotAffected && statement.Justification == "" && statement.ImpactStatement == "" {
			statement.ImpactStatement = firstNonEmptyString(row.Reason, "Assessed not affected.")
		}
		if (status == vex.StatusAffected || status == vex.StatusUnderInvestigation) && statement.ActionStatement == "" && measures != "" {
			statement.ActionStatement = measures
		}
		statements = append(statements, statement)
		notice.Rows = append(notice.Rows, noticeRow{Version: row.Label, Status: strings.ReplaceAll(status, "_", " "), Detail: firstNonEmptyString(statement.ActionStatement, statement.ImpactStatement, detail)})
	}
	// Severe incidents scope clients directly.
	for _, row := range scope {
		if row.SubjectType == incident.ScopeClient && row.SubjectID == client.ID.String() && len(statements) == 0 {
			statements = append(statements, vex.Statement{VulnerabilityID: identifier, Status: vex.StatusAffected, ActionStatement: measures, ProductPURL: product.PURL, ProductName: product.Name})
			notice.Rows = append(notice.Rows, noticeRow{Version: "all versions", Status: "affected", Detail: measures})
		}
	}
	if len(statements) == 0 {
		return nil, errIncidentInput("%s runs no release in this incident's scope", client.Name)
	}
	sort.SliceStable(notice.Rows, func(i, j int) bool { return notice.Rows[i].Version < notice.Rows[j].Version })

	previous, err := db.ListClientDeliveryTimes(ctx, dbgen.ListClientDeliveryTimesParams{IncidentID: inc.ID, ClientID: uuid.NullUUID{UUID: client.ID, Valid: true}})
	if err != nil {
		return nil, err
	}
	version := len(previous) + 1
	initial := now
	revisions := []vex.ExportRevision{}
	for index, at := range previous {
		if index == 0 {
			initial = at
		}
		revisions = append(revisions, vex.ExportRevision{Number: strconv.Itoa(index + 1), Date: at, Summary: "Notice version " + strconv.Itoa(index+1)})
	}
	revisions = append(revisions, vex.ExportRevision{Number: strconv.Itoa(version), Date: now, Summary: map[bool]string{true: "Initial notice", false: "Updated notice"}[version == 1]})
	notice.Version = version

	tracking := fmt.Sprintf("%s-INC-%d-%s", strings.ToUpper(org.Slug), inc.Number, strings.ToUpper(client.Slug))
	meta := documentMeta{
		Author: firstNonEmptyString(org.DisplayName, org.Name) + " product security", PublisherCategory: "vendor",
		PublisherName: firstNonEmptyString(org.DisplayName, org.Name), PublisherNamespace: s.vexPublisherNamespace(org),
		TrackingID: tracking, TLP: "TLP:AMBER", Title: inc.Title, Timestamp: now, InitialTimestamp: initial,
		Version: version, Revisions: revisions,
	}
	out := make([]documentInputs, 0, len(clientDocumentKinds))
	for _, kind := range clientDocumentKinds {
		docMeta := meta
		docMeta.DocumentID = tracking + "-" + kind + "-v" + strconv.Itoa(version)
		if kind == docCycloneDX {
			docMeta.DocumentID = "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, []byte(tracking+"/"+kind+"/"+strconv.Itoa(version))).String()
		}
		in := documentInputs{Kind: kind, Meta: docMeta, Statements: statements}
		if kind == docCSAFAdvisory {
			in.Advisories = []vex.AdvisoryInfo{advisoryInfo}
		}
		if kind == docNoticeHTML || kind == docNoticeText {
			noticeCopy := notice
			in.Notice = &noticeCopy
			in.Statements = nil
		}
		out = append(out, in)
	}
	return out, nil
}

// clientFacingStatus maps a scope status to the VEX status a client reads.
// Pending and unknown read as under investigation: they are still being
// assessed, and a notice says so rather than guessing.
func clientFacingStatus(status string) (string, string) {
	switch status {
	case incident.ScopeAffected:
		return vex.StatusAffected, ""
	case incident.ScopeNotAffected:
		return vex.StatusNotAffected, ""
	case incident.ScopeFixed:
		return vex.StatusFixed, ""
	case incident.ScopePending, incident.ScopeUnderInvestigation:
		return vex.StatusUnderInvestigation, "being assessed"
	case incident.ScopeUnknown:
		return vex.StatusUnderInvestigation, "inventory being produced for this version"
	}
	return "", ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// securityContact is one entry of clients.security_contacts.
type securityContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

func securityContactEmails(client dbgen.Client) []string {
	var contacts []securityContact
	_ = json.Unmarshal(client.SecurityContacts, &contacts)
	out := []string{}
	for _, contact := range contacts {
		if email := strings.TrimSpace(contact.Email); email != "" {
			out = append(out, email)
		}
	}
	if len(out) == 0 && client.ContactEmail.Valid && strings.TrimSpace(client.ContactEmail.String) != "" {
		out = append(out, strings.TrimSpace(client.ContactEmail.String))
	}
	return out
}
