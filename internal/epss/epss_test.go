package epss

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const sample = `#model_version:v2025.03.14,score_date:2026-10-09T12:00:22Z
cve,epss,percentile
CVE-2020-0601,0.94398,0.99843
cve-2023-44487,0.94427,0.99980
`

func TestParse(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(sample))
	_ = zw.Close()

	catalog, err := Parse(&buf, true)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.ModelVersion != "v2025.03.14" || catalog.ScoreDate.Format("2006-01-02") != "2026-10-09" {
		t.Fatalf("model line: %+v", catalog)
	}
	if len(catalog.Scores) != 2 || catalog.Scores[1].CVEID != "CVE-2023-44487" || catalog.Scores[0].Percentile != 0.99843 {
		t.Fatalf("scores: %+v", catalog.Scores)
	}
}

func TestParseRejectsBadFiles(t *testing.T) {
	for name, body := range map[string]string{
		"no model line": "cve,epss,percentile\nCVE-2020-0601,0.9,0.9\n",
		"bad header":    "#model_version:v1,score_date:2026-10-09\ncve,score\n",
		"out of range":  "#model_version:v1,score_date:2026-10-09\ncve,epss,percentile\nCVE-2020-0601,1.5,0.9\n",
		"not a cve":     "#model_version:v1,score_date:2026-10-09\ncve,epss,percentile\nGHSA-x,0.5,0.9\n",
	} {
		if _, err := Parse(strings.NewReader(body), false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
