package trivy

// Wire types for the Trivy Twirp (JSON) API. Field names use snake_case to match
// the server's JSON encoding for both requests and responses.

type pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type application struct {
	Type     string `json:"type"`
	FilePath string `json:"file_path"`
	Packages []pkg  `json:"packages"`
}

type osInfo struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type osPkg struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Release    string `json:"release,omitempty"`
	Epoch      int    `json:"epoch,omitempty"`
	SrcName    string `json:"src_name,omitempty"`
	SrcVersion string `json:"src_version,omitempty"`
	SrcRelease string `json:"src_release,omitempty"`
	SrcEpoch   int    `json:"src_epoch,omitempty"`
}

type packageInfo struct {
	FilePath string  `json:"file_path,omitempty"`
	Packages []osPkg `json:"packages"`
}

type blobInfo struct {
	SchemaVersion int           `json:"schema_version"`
	OS            *osInfo       `json:"os,omitempty"`
	PackageInfos  []packageInfo `json:"package_infos,omitempty"`
	Applications  []application `json:"applications,omitempty"`
}

type putBlobRequest struct {
	DiffID   string   `json:"diff_id"`
	BlobInfo blobInfo `json:"blob_info"`
}

type artifactInfo struct {
	SchemaVersion int `json:"schema_version"`
}

type putArtifactRequest struct {
	ArtifactID   string       `json:"artifact_id"`
	ArtifactInfo artifactInfo `json:"artifact_info"`
}

type scanOptions struct {
	PkgTypes []string `json:"pkg_types"`
	Scanners []string `json:"scanners"`
}

type scanRequest struct {
	Target     string      `json:"target"`
	ArtifactID string      `json:"artifact_id"`
	BlobIDs    []string    `json:"blob_ids"`
	Options    scanOptions `json:"options"`
}

type scanResponse struct {
	Results []scanResult `json:"results"`
}

type scanResult struct {
	Target          string               `json:"target"`
	Type            string               `json:"type"`
	Class           string               `json:"class"`
	Vulnerabilities []trivyVulnerability `json:"vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"vulnerability_id"`
	PkgName          string `json:"pkg_name"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	// SeveritySource names whose rating Severity is (the distro vendor for an
	// OS package); VendorSeverity is every vendor's own label.
	SeveritySource   string               `json:"severity_source,omitempty"`
	VendorSeverity   map[string]string    `json:"vendor_severity,omitempty"`
	References       []string             `json:"references"`
	CweIDs           []string             `json:"cwe_ids"`
	PrimaryURL       string               `json:"primary_url"`
	CVSS             map[string]trivyCVSS `json:"cvss"`
	PublishedDate    string               `json:"published_date"`
	LastModifiedDate string               `json:"last_modified_date"`
}

type trivyCVSS struct {
	V2Vector  string  `json:"v2_vector"`
	V3Vector  string  `json:"v3_vector"`
	V2Score   float64 `json:"v2_score"`
	V3Score   float64 `json:"v3_score"`
	V40Vector string  `json:"v40_vector"`
	V40Score  float64 `json:"v40_score"`
}
