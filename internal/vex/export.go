package vex

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The exporters render statements into OpenVEX, CycloneDX VEX and CSAF
// (ADR-053 §5). They are deterministic: the same statements and metadata give
// the same bytes — statements are sorted, every timestamp and identifier comes
// from the metadata, maps never reach the encoder — so a document sent once
// can be re-rendered from its recorded inputs and compared byte for byte.
// RendererVersion names the output contract; it changes whenever the bytes
// for identical inputs would.
const RendererVersion = "hibou-vex/2"

var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d+$`)

type ExportPublisher struct {
	Category  string
	Name      string
	Namespace string
}

type ExportRevision struct {
	Number  string
	Date    time.Time
	Summary string
}

type ExportMeta struct {
	Author     string
	Publisher  ExportPublisher
	DocumentID string
	TrackingID string
	TLPLabel   string
	// Timestamp is the document's current release date; InitialTimestamp the
	// first release (defaults to Timestamp). Both must come from the caller:
	// an exporter that read the clock could not be verified later.
	Timestamp        time.Time
	InitialTimestamp time.Time
	Version          int
	Revisions        []ExportRevision
	Title            string
}

// AdvisoryInfo carries what a CSAF security advisory states about each
// vulnerability beyond the per-product status (Art. 14(8) user notice).
type AdvisoryInfo struct {
	VulnerabilityID string
	Title           string
	Description     string
	CVSSVersion     string
	CVSSScore       float64
	CVSSVector      string
	// ExploitStatus is the threat text, e.g. "Exploitation observed".
	ExploitStatus string
	References    []string
}

func metaTimestamp(meta ExportMeta) (string, string) {
	current := meta.Timestamp.UTC()
	if meta.Timestamp.IsZero() {
		current = time.Unix(0, 0).UTC()
	}
	initial := current
	if !meta.InitialTimestamp.IsZero() {
		initial = meta.InitialTimestamp.UTC()
	}
	return current.Format(time.RFC3339), initial.Format(time.RFC3339)
}

func sortedStatements(statements []Statement) []Statement {
	out := make([]Statement, len(statements))
	copy(out, statements)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.VulnerabilityID != b.VulnerabilityID {
			return a.VulnerabilityID < b.VulnerabilityID
		}
		if productKey(a) != productKey(b) {
			return productKey(a) < productKey(b)
		}
		return a.ComponentPURL < b.ComponentPURL
	})
	return out
}

// productRef is the identifier a statement's product goes by: the product
// purl with its version, or — for statements without a product axis — the
// component, which older statements treated as the product.
func productRef(statement Statement) string {
	if purl := strings.TrimSpace(statement.ProductPURL); purl != "" {
		if version := strings.TrimSpace(statement.ProductVersion); version != "" {
			return purl + "@" + version
		}
		return purl
	}
	return strings.TrimSpace(statement.ComponentPURL)
}

func productKey(statement Statement) string {
	return productRef(statement) + "|" + strings.TrimSpace(statement.ProductVersion)
}

// ExportOpenVEX renders an OpenVEX v0.2.0 document.
func ExportOpenVEX(statements []Statement, meta ExportMeta) ([]byte, error) {
	timestamp, _ := metaTimestamp(meta)
	type component struct {
		ID string `json:"@id"`
	}
	type product struct {
		ID            string      `json:"@id"`
		Subcomponents []component `json:"subcomponents,omitempty"`
	}
	type vulnerability struct {
		Name    string   `json:"name"`
		Aliases []string `json:"aliases,omitempty"`
	}
	type statementOut struct {
		Vulnerability   vulnerability `json:"vulnerability"`
		Products        []product     `json:"products,omitempty"`
		Status          string        `json:"status"`
		Justification   string        `json:"justification,omitempty"`
		ImpactStatement string        `json:"impact_statement,omitempty"`
		ActionStatement string        `json:"action_statement,omitempty"`
	}
	type document struct {
		Context    string         `json:"@context"`
		ID         string         `json:"@id"`
		Author     string         `json:"author"`
		Timestamp  string         `json:"timestamp"`
		Version    int            `json:"version"`
		Statements []statementOut `json:"statements"`
	}

	items := make([]statementOut, 0, len(statements))
	for _, statement := range sortedStatements(statements) {
		item := statementOut{
			Vulnerability:   vulnerability{Name: strings.TrimSpace(statement.VulnerabilityID), Aliases: sortedUnique(statement.Aliases, statement.VulnerabilityID)},
			Status:          strings.TrimSpace(statement.Status),
			Justification:   strings.TrimSpace(statement.Justification),
			ImpactStatement: strings.TrimSpace(statement.ImpactStatement),
			ActionStatement: strings.TrimSpace(statement.ActionStatement),
		}
		if item.Status == StatusNotAffected && item.Justification == "" && item.ImpactStatement == "" {
			return nil, fmt.Errorf("statement %s: not_affected needs a justification or an impact statement", item.Vulnerability.Name)
		}
		if ref := productRef(statement); ref != "" {
			p := product{ID: ref}
			if strings.TrimSpace(statement.ProductPURL) != "" {
				if componentPURL := strings.TrimSpace(statement.ComponentPURL); componentPURL != "" {
					p.Subcomponents = []component{{ID: componentPURL}}
				}
			}
			item.Products = []product{p}
		}
		items = append(items, item)
	}
	author := strings.TrimSpace(meta.Author)
	if author == "" {
		author = strings.TrimSpace(meta.Publisher.Name)
	}
	version := meta.Version
	if version < 1 {
		version = 1
	}
	return json.MarshalIndent(document{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         strings.TrimSpace(meta.DocumentID),
		Author:     author,
		Timestamp:  timestamp,
		Version:    version,
		Statements: items,
	}, "", "  ")
}

// ExportCycloneDX renders a CycloneDX 1.6 VEX BOM: the product is the BOM's
// metadata component when every statement names the same product, and each
// affected component is a `bom-ref` the vulnerabilities point at.
func ExportCycloneDX(statements []Statement, meta ExportMeta) ([]byte, error) {
	timestamp, _ := metaTimestamp(meta)
	type component struct {
		Type    string `json:"type"`
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
		CPE     string `json:"cpe,omitempty"`
	}
	type source struct {
		Name string `json:"name"`
	}
	type analysis struct {
		State         string   `json:"state"`
		Justification string   `json:"justification,omitempty"`
		Response      []string `json:"response,omitempty"`
		Detail        string   `json:"detail,omitempty"`
	}
	type affects struct {
		Ref string `json:"ref"`
	}
	type reference struct {
		ID     string `json:"id"`
		Source source `json:"source"`
	}
	type vulnerability struct {
		BOMRef     string      `json:"bom-ref"`
		ID         string      `json:"id"`
		Source     *source     `json:"source,omitempty"`
		References []reference `json:"references,omitempty"`
		Analysis   analysis    `json:"analysis"`
		Affects    []affects   `json:"affects"`
	}
	type metadata struct {
		Timestamp string     `json:"timestamp"`
		Component *component `json:"component,omitempty"`
	}
	type bom struct {
		BOMFormat       string          `json:"bomFormat"`
		SpecVersion     string          `json:"specVersion"`
		SerialNumber    string          `json:"serialNumber,omitempty"`
		Version         int             `json:"version"`
		Metadata        metadata        `json:"metadata"`
		Components      []component     `json:"components,omitempty"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	}

	sorted := sortedStatements(statements)
	doc := bom{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: max(meta.Version, 1), Metadata: metadata{Timestamp: timestamp}}
	if id := strings.TrimSpace(meta.DocumentID); strings.HasPrefix(id, "urn:uuid:") {
		doc.SerialNumber = id
	}
	products := map[string]component{}
	componentRefs := map[string]component{}
	for _, statement := range sorted {
		if purl := strings.TrimSpace(statement.ProductPURL); purl != "" {
			ref := productRef(statement)
			products[ref] = component{Type: "application", BOMRef: ref, Name: productDisplayName(statement), Version: strings.TrimSpace(statement.ProductVersion), PURL: ref, CPE: strings.TrimSpace(statement.ProductCPE)}
		}
		if componentPURL := strings.TrimSpace(statement.ComponentPURL); componentPURL != "" {
			name, version := purlNameVersion(componentPURL)
			componentRefs[componentPURL] = component{Type: "library", BOMRef: componentPURL, Name: name, Version: version, PURL: componentPURL}
		}
	}
	productKeys := sortedKeys(products)
	if len(productKeys) == 1 {
		single := products[productKeys[0]]
		doc.Metadata.Component = &single
	} else {
		for _, key := range productKeys {
			doc.Components = append(doc.Components, products[key])
		}
	}
	for _, key := range sortedKeys(componentRefs) {
		doc.Components = append(doc.Components, componentRefs[key])
	}
	for index, statement := range sorted {
		id := strings.TrimSpace(statement.VulnerabilityID)
		item := vulnerability{
			BOMRef: fmt.Sprintf("vuln-%d", index+1),
			ID:     id,
			Analysis: analysis{
				State:         cycloneDXState(statement.Status),
				Justification: cycloneDXJustification(statement.Justification),
				Detail:        strings.TrimSpace(firstNonEmpty(statement.ImpactStatement, statement.ActionStatement)),
			},
		}
		if system := identifierSystemName(id); system != "" {
			item.Source = &source{Name: system}
		}
		for _, alias := range sortedUnique(statement.Aliases, id) {
			item.References = append(item.References, reference{ID: alias, Source: source{Name: identifierSystemName(alias)}})
		}
		if statement.Status == StatusAffected && strings.TrimSpace(statement.ActionStatement) != "" {
			item.Analysis.Response = []string{"workaround_available"}
		}
		target := strings.TrimSpace(statement.ComponentPURL)
		if target == "" {
			target = productRef(statement)
		}
		if target != "" {
			item.Affects = []affects{{Ref: target}}
		} else {
			item.Affects = []affects{}
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, item)
	}
	if doc.Vulnerabilities == nil {
		doc.Vulnerabilities = []vulnerability{}
	}
	return json.MarshalIndent(doc, "", "  ")
}

func cycloneDXState(status string) string {
	switch strings.TrimSpace(status) {
	case StatusNotAffected:
		return "not_affected"
	case StatusAffected:
		return "exploitable"
	case StatusFixed:
		return "resolved"
	default:
		return "in_triage"
	}
}

// cycloneDXJustification maps the CISA vocabulary onto CycloneDX's.
func cycloneDXJustification(justification string) string {
	switch strings.TrimSpace(justification) {
	case JustComponentNotPresent, JustVulnerableCodeNotPresent:
		return "code_not_present"
	case JustCodeNotInExecutePath:
		return "code_not_reachable"
	case JustCodeCannotBeControlled:
		return "protected_by_mitigating_control"
	case JustInlineMitigationsExist:
		return "protected_at_runtime"
	default:
		return ""
	}
}

// ExportCSAF renders a CSAF 2.0 document of category csaf_vex.
func ExportCSAF(statements []Statement, meta ExportMeta) ([]byte, error) {
	return exportCSAF("csaf_vex", statements, meta, nil)
}

// ExportCSAFAdvisory renders a CSAF 2.0 csaf_security_advisory: the per-version
// status of a csaf_vex document plus description, scores and exploitation
// threats — the shape of the Art. 14(8) notice to users (ADR-053 §5).
func ExportCSAFAdvisory(statements []Statement, meta ExportMeta, info []AdvisoryInfo) ([]byte, error) {
	return exportCSAF("csaf_security_advisory", statements, meta, info)
}

type csafOutHelper struct {
	CPE  string `json:"cpe,omitempty"`
	PURL string `json:"purl,omitempty"`
}

type csafOutProduct struct {
	ProductID string         `json:"product_id"`
	Name      string         `json:"name"`
	Helper    *csafOutHelper `json:"product_identification_helper,omitempty"`
}

type csafOutBranch struct {
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Product  *csafOutProduct `json:"product,omitempty"`
	Branches []csafOutBranch `json:"branches,omitempty"`
}

type csafOutNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

type csafOutID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type csafOutFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

type csafOutThreat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type csafOutRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type csafOutCVSS struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type csafOutScore struct {
	CVSSv3   *csafOutCVSS `json:"cvss_v3,omitempty"`
	Products []string     `json:"products"`
}

type csafOutReference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type csafOutStatus struct {
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type csafOutVulnerability struct {
	CVE           string               `json:"cve,omitempty"`
	IDs           []csafOutID          `json:"ids,omitempty"`
	Title         string               `json:"title,omitempty"`
	Notes         []csafOutNote        `json:"notes,omitempty"`
	ProductStatus csafOutStatus        `json:"product_status"`
	Flags         []csafOutFlag        `json:"flags,omitempty"`
	Threats       []csafOutThreat      `json:"threats,omitempty"`
	Remediations  []csafOutRemediation `json:"remediations,omitempty"`
	Scores        []csafOutScore       `json:"scores,omitempty"`
	References    []csafOutReference   `json:"references,omitempty"`
}

type csafOutRevision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type csafOutDocument struct {
	Document struct {
		Category     string `json:"category"`
		CsafVersion  string `json:"csaf_version"`
		Distribution struct {
			TLP struct {
				Label string `json:"label"`
			} `json:"tlp"`
		} `json:"distribution"`
		Publisher struct {
			Category  string `json:"category"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"publisher"`
		Title    string `json:"title"`
		Tracking struct {
			CurrentReleaseDate string `json:"current_release_date"`
			Generator          struct {
				Engine struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"engine"`
			} `json:"generator"`
			ID                 string            `json:"id"`
			InitialReleaseDate string            `json:"initial_release_date"`
			RevisionHistory    []csafOutRevision `json:"revision_history"`
			Status             string            `json:"status"`
			Version            string            `json:"version"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches []csafOutBranch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []csafOutVulnerability `json:"vulnerabilities"`
}

func exportCSAF(category string, statements []Statement, meta ExportMeta, info []AdvisoryInfo) ([]byte, error) {
	current, initial := metaTimestamp(meta)
	vendor := strings.TrimSpace(meta.Publisher.Name)
	if vendor == "" {
		vendor = "hibou"
	}
	sorted := sortedStatements(statements)

	// Products: one per product ref, identified deterministically.
	type productEntry struct {
		id, name, version, purl, cpe string
	}
	products := map[string]productEntry{}
	usedIDs := map[string]int{}
	productIDFor := func(statement Statement) string {
		ref := productRef(statement)
		if ref == "" {
			ref = "unspecified"
		}
		if entry, ok := products[ref]; ok {
			return entry.id
		}
		base := csafProductIDBase(statement)
		usedIDs[base]++
		id := base
		if usedIDs[base] > 1 {
			id = fmt.Sprintf("%s-%d", base, usedIDs[base])
		}
		version := strings.TrimSpace(statement.ProductVersion)
		name := productDisplayName(statement)
		if strings.TrimSpace(statement.ProductPURL) == "" {
			name, version = purlNameVersion(ref)
		}
		purl := ref
		if !strings.HasPrefix(purl, "pkg:") {
			purl = ""
		}
		products[ref] = productEntry{id: id, name: name, version: version, purl: purl, cpe: strings.TrimSpace(statement.ProductCPE)}
		return id
	}

	vulnOrder := []string{}
	vulns := map[string]*csafOutVulnerability{}
	for _, statement := range sorted {
		key := strings.TrimSpace(statement.VulnerabilityID)
		entry, ok := vulns[key]
		if !ok {
			entry = &csafOutVulnerability{}
			if cveIDPattern.MatchString(key) {
				entry.CVE = strings.ToUpper(key)
			} else if key != "" {
				entry.IDs = append(entry.IDs, csafOutID{SystemName: identifierSystemName(key), Text: key})
			}
			for _, alias := range sortedUnique(statement.Aliases, key) {
				if entry.CVE == "" && cveIDPattern.MatchString(alias) {
					entry.CVE = strings.ToUpper(alias)
					continue
				}
				entry.IDs = append(entry.IDs, csafOutID{SystemName: identifierSystemName(alias), Text: alias})
			}
			vulns[key] = entry
			vulnOrder = append(vulnOrder, key)
		}
		productID := productIDFor(statement)
		switch strings.TrimSpace(statement.Status) {
		case StatusNotAffected:
			entry.ProductStatus.KnownNotAffected = appendUnique(entry.ProductStatus.KnownNotAffected, productID)
			if justification := strings.TrimSpace(statement.Justification); justification != "" {
				entry.Flags = appendFlag(entry.Flags, justification, productID)
			} else if strings.TrimSpace(statement.ImpactStatement) == "" {
				return nil, fmt.Errorf("statement %s: not_affected needs a justification or an impact statement", key)
			}
		case StatusAffected:
			entry.ProductStatus.KnownAffected = appendUnique(entry.ProductStatus.KnownAffected, productID)
		case StatusFixed:
			entry.ProductStatus.Fixed = appendUnique(entry.ProductStatus.Fixed, productID)
		default:
			entry.ProductStatus.UnderInvestigation = appendUnique(entry.ProductStatus.UnderInvestigation, productID)
		}
		if impact := strings.TrimSpace(statement.ImpactStatement); impact != "" {
			entry.Threats = append(entry.Threats, csafOutThreat{Category: "impact", Details: impact, ProductIDs: []string{productID}})
		}
		if action := strings.TrimSpace(statement.ActionStatement); action != "" {
			category := "mitigation"
			if statement.Status == StatusFixed {
				category = "vendor_fix"
			}
			entry.Remediations = append(entry.Remediations, csafOutRemediation{Category: category, Details: action, ProductIDs: []string{productID}})
		}
	}

	infoByID := map[string]AdvisoryInfo{}
	for _, item := range info {
		infoByID[strings.TrimSpace(item.VulnerabilityID)] = item
	}
	var doc csafOutDocument
	doc.Document.Category = category
	doc.Document.CsafVersion = "2.0"
	doc.Document.Distribution.TLP.Label = csafTLPLabel(meta.TLPLabel)
	doc.Document.Publisher.Category = firstNonEmpty(strings.TrimSpace(meta.Publisher.Category), "vendor")
	doc.Document.Publisher.Name = vendor
	doc.Document.Publisher.Namespace = firstNonEmpty(strings.TrimSpace(meta.Publisher.Namespace), "https://example.invalid")
	doc.Document.Title = firstNonEmpty(strings.TrimSpace(meta.Title), vendor+" VEX")
	tracking := &doc.Document.Tracking
	tracking.ID = firstNonEmpty(strings.TrimSpace(meta.TrackingID), strings.TrimSpace(meta.DocumentID), "hibou-vex")
	tracking.CurrentReleaseDate = current
	tracking.InitialReleaseDate = initial
	tracking.Status = "final"
	tracking.Generator.Engine.Name = "hibou"
	tracking.Generator.Engine.Version = RendererVersion
	version := max(meta.Version, 1)
	tracking.Version = strconv.Itoa(version)
	if len(meta.Revisions) > 0 {
		for _, revision := range meta.Revisions {
			tracking.RevisionHistory = append(tracking.RevisionHistory, csafOutRevision{Date: revision.Date.UTC().Format(time.RFC3339), Number: revision.Number, Summary: revision.Summary})
		}
	} else {
		tracking.RevisionHistory = []csafOutRevision{{Date: current, Number: tracking.Version, Summary: "Initial release"}}
	}

	// Product tree: vendor → product name → product version.
	byName := map[string][]productEntry{}
	for _, entry := range products {
		byName[entry.name] = append(byName[entry.name], entry)
	}
	vendorBranch := csafOutBranch{Category: "vendor", Name: vendor}
	for _, name := range sortedKeys(byName) {
		entries := byName[name]
		sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
		nameBranch := csafOutBranch{Category: "product_name", Name: name}
		for _, entry := range entries {
			product := &csafOutProduct{ProductID: entry.id, Name: strings.TrimSpace(name + " " + entry.version)}
			if entry.purl != "" || entry.cpe != "" {
				product.Helper = &csafOutHelper{PURL: entry.purl, CPE: entry.cpe}
			}
			nameBranch.Branches = append(nameBranch.Branches, csafOutBranch{Category: "product_version", Name: firstNonEmpty(entry.version, "all versions"), Product: product})
		}
		vendorBranch.Branches = append(vendorBranch.Branches, nameBranch)
	}
	doc.ProductTree.Branches = []csafOutBranch{vendorBranch}

	for _, key := range vulnOrder {
		entry := vulns[key]
		// CSAF 2.0 profiles 4 and 5 require notes on every vulnerability, and
		// a remediation for every known-affected product (tests 6.1.27.9-10).
		affectedWithoutRemediation := []string{}
		for _, productID := range entry.ProductStatus.KnownAffected {
			covered := false
			for _, remediation := range entry.Remediations {
				for _, id := range remediation.ProductIDs {
					covered = covered || id == productID
				}
			}
			if !covered {
				affectedWithoutRemediation = append(affectedWithoutRemediation, productID)
			}
		}
		if len(affectedWithoutRemediation) > 0 {
			entry.Remediations = append(entry.Remediations, csafOutRemediation{Category: "none_available", Details: "No remediation is recorded yet.", ProductIDs: affectedWithoutRemediation})
		}
		item, hasInfo := infoByID[key]
		if description := strings.TrimSpace(item.Description); hasInfo && description != "" {
			entry.Notes = append(entry.Notes, csafOutNote{Category: "description", Text: description, Title: "Description"})
		} else {
			entry.Notes = append(entry.Notes, csafOutNote{Category: "general", Text: "Status of each product version as assessed by " + vendor + ".", Title: "Assessment"})
		}
		if hasInfo {
			entry.Title = strings.TrimSpace(item.Title)
			affected := append(append([]string{}, entry.ProductStatus.KnownAffected...), entry.ProductStatus.UnderInvestigation...)
			if item.CVSSScore > 0 && strings.TrimSpace(item.CVSSVector) != "" && strings.HasPrefix(item.CVSSVersion, "3") && len(affected) > 0 {
				entry.Scores = append(entry.Scores, csafOutScore{CVSSv3: &csafOutCVSS{Version: item.CVSSVersion, VectorString: item.CVSSVector, BaseScore: item.CVSSScore, BaseSeverity: cvssSeverity(item.CVSSScore)}, Products: affected})
			}
			if status := strings.TrimSpace(item.ExploitStatus); status != "" && len(affected) > 0 {
				entry.Threats = append(entry.Threats, csafOutThreat{Category: "exploit_status", Details: status, ProductIDs: affected})
			}
			for _, url := range sortedUnique(item.References, "") {
				entry.References = append(entry.References, csafOutReference{Category: "external", Summary: url, URL: url})
			}
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, *entry)
	}
	if doc.Vulnerabilities == nil {
		doc.Vulnerabilities = []csafOutVulnerability{}
	}
	return json.MarshalIndent(doc, "", "  ")
}

// csafTLPLabel maps a TLP label onto the CSAF 2.0 vocabulary, which predates
// TLP 2.0: CLEAR is written WHITE there, and the "TLP:" prefix is not used.
func csafTLPLabel(label string) string {
	normalized := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(label)), "TLP:")
	switch normalized {
	case "GREEN", "AMBER", "RED", "WHITE":
		return normalized
	case "AMBER+STRICT":
		return "AMBER"
	default:
		return "WHITE"
	}
}

func cvssSeverity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendFlag(flags []csafOutFlag, label, productID string) []csafOutFlag {
	for i := range flags {
		if flags[i].Label == label {
			flags[i].ProductIDs = appendUnique(flags[i].ProductIDs, productID)
			return flags
		}
	}
	return append(flags, csafOutFlag{Label: label, ProductIDs: []string{productID}})
}

var csafIDUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func csafProductIDBase(statement Statement) string {
	name := productDisplayName(statement)
	version := strings.TrimSpace(statement.ProductVersion)
	if strings.TrimSpace(statement.ProductPURL) == "" {
		name, version = purlNameVersion(productRef(statement))
	}
	base := strings.Trim(csafIDUnsafe.ReplaceAllString(name, "-"), "-")
	if base == "" {
		base = "product"
	}
	if version != "" {
		base += "-" + strings.Trim(csafIDUnsafe.ReplaceAllString(version, "-"), "-")
	}
	return strings.ToUpper(base)
}

func productDisplayName(statement Statement) string {
	if name := strings.TrimSpace(statement.ProductName); name != "" {
		return name
	}
	if purl := strings.TrimSpace(statement.ProductPURL); purl != "" {
		name, _ := purlNameVersion(purl)
		return name
	}
	if supplier := strings.TrimSpace(statement.Supplier); supplier != "" && strings.TrimSpace(statement.ComponentPURL) == "" {
		return supplier
	}
	return "org-wide"
}

// purlNameVersion splits a purl into its last name segment and version.
func purlNameVersion(purl string) (string, string) {
	trimmed := strings.TrimSpace(purl)
	if trimmed == "" {
		return "", ""
	}
	if index := strings.IndexAny(trimmed, "?#"); index >= 0 {
		trimmed = trimmed[:index]
	}
	name, version := trimmed, ""
	if at := strings.LastIndex(trimmed, "@"); at > strings.LastIndex(trimmed, "/") {
		name, version = trimmed[:at], trimmed[at+1:]
	}
	if slash := strings.LastIndex(name, "/"); slash >= 0 && slash < len(name)-1 {
		name = name[slash+1:]
	}
	return name, version
}

func identifierSystemName(vulnerabilityID string) string {
	trimmed := strings.TrimSpace(vulnerabilityID)
	if trimmed == "" {
		return "hibou"
	}
	if index := strings.Index(trimmed, "-"); index > 0 {
		return strings.ToUpper(trimmed[:index])
	}
	return "hibou"
}

func sortedUnique(values []string, exclude string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, strings.TrimSpace(exclude)) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
