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
