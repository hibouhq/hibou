package cvefeed

// The CVE Record Format 5.x subset this package reads. Only the fields the
// projection needs are declared; the published records carry a great deal more
// (CPE applicability, SSVC decision points, supporting media, taxonomy
// mappings) that hibou does not consume.
type record struct {
	Metadata struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Assigner  string `json:"assignerShortName"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA container   `json:"cna"`
		ADP []container `json:"adp"`
	} `json:"containers"`
}

// container is both the cna and each adp entry: Authorized Data Publishers
// enrich the same record in the same shape, which is why CISA's CVSS costs no
// extra request.
type container struct {
	ProviderMetadata struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Affected     []affected    `json:"affected"`
	Descriptions []description `json:"descriptions"`
	Metrics      []metric      `json:"metrics"`
	ProblemTypes []problemType `json:"problemTypes"`
	References   []reference   `json:"references"`
}

type affected struct {
	Vendor        string         `json:"vendor"`
	Product       string         `json:"product"`
	DefaultStatus string         `json:"defaultStatus"`
	Versions      []versionEntry `json:"versions"`
}

type versionEntry struct {
	Version         string `json:"version"`
	Status          string `json:"status"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	VersionType     string `json:"versionType"`
}

type description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type problemType struct {
	Descriptions []struct {
		CWEID string `json:"cweId"`
		Type  string `json:"type"`
	} `json:"descriptions"`
}

type reference struct {
	URL string `json:"url"`
}

// metric holds whichever CVSS versions a container supplied. The `other` shape
// carries free text ("low") rather than a score, which is why bestSeverity
// prefers any structured vector over it.
type metric struct {
	CVSSv4  *cvss `json:"cvssV4_0"`
	CVSSv31 *cvss `json:"cvssV3_1"`
	CVSSv30 *cvss `json:"cvssV3_0"`
	Other   *struct {
		Type    string `json:"type"`
		Content struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"other"`
}

type cvss struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}
