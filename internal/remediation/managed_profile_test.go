package remediation

import "testing"

func TestManagedProfileRejectsAncestorControls(t *testing.T) {
	for _, file := range []string{".npmrc", ".nvmrc", "apps/.node-version", "apps/web/.tool-versions"} {
		if managedNPMControlReason("apps/web/package.json", []string{file}) == "" {
			t.Fatalf("ancestor configuration silently omitted: %s", file)
		}
	}
	if reason := managedNPMControlReason("apps/web/package.json", []string{"other/.npmrc", "apps/another/.node-version"}); reason != "" {
		t.Fatalf("unrelated module blocked: %s", reason)
	}
}
