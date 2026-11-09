package vex

const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

const (
	JustComponentNotPresent      = "component_not_present"
	JustVulnerableCodeNotPresent = "vulnerable_code_not_present"
	JustCodeNotInExecutePath     = "vulnerable_code_not_in_execute_path"
	JustCodeCannotBeControlled   = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustInlineMitigationsExist   = "inline_mitigations_already_exist"
)

const (
	SourceManual     = "manual"
	SourceImported   = "imported"
	SourcePropagated = "propagated"
	SourceAutomated  = "automated"
)

type Statement struct {
	VulnerabilityID   string
	Status            string
	Justification     string
	ImpactStatement   string
	ActionStatement   string
	ComponentPURL     string
	Supplier          string
	SourceDocumentURL string
	// ProductPURL names the product the statement is about, version-less
	// (pkg:generic/<vendor>/<product>); ProductVersion narrows it to one
	// release. When set, ComponentPURL is the subcomponent carrying the
	// vulnerability, not the product (ADR-053 §4a). Empty keeps the older
	// reading where the component is the product.
	ProductPURL    string
	ProductName    string
	ProductVersion string
	ProductCPE     string
	// Aliases are the advisory's other identifiers, carried into formats that
	// hold them.
	Aliases []string
}

type ParseResult struct {
	Format     string
	Statements []Statement
	DocumentID string
	Timestamp  string
}

const (
	FormatOpenVEX   = "openvex"
	FormatCSAF      = "csaf"
	FormatCycloneDX = "cyclonedx"
)
