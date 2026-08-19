package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	DocumentNS  string        `json:"documentNamespace"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceLocator  string `json:"referenceLocator"`
	ReferenceType     string `json:"referenceType"`
}

func ParseSPDXJSON(data []byte) ([]ParsedComponent, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode spdx json: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(doc.SPDXVersion)), "SPDX-") {
		return nil, errors.New("sbom is not an SPDX JSON document")
	}

	components := make([]ParsedComponent, 0, len(doc.Packages))
	documentNamePrefix := strings.TrimSpace(doc.DocumentNS)
	if documentNamePrefix != "" && !strings.HasSuffix(documentNamePrefix, "#") {
		documentNamePrefix += "#"
	}
	for _, pkg := range doc.Packages {
		if shouldSkipSPDXPackage(pkg, documentNamePrefix) {
			continue
		}

		version := strings.TrimSpace(pkg.VersionInfo)
		purl := spdxPackagePURL(pkg.ExternalRefs)
		name := canonicalComponentName(purl, "", pkg.Name)
		ecosystem := ecosystemFromPURL(purl)
		components = append(components, ParsedComponent{
			PURL:      purl,
			Name:      name,
			Version:   version,
			Ecosystem: ecosystem,
			Licenses:  spdxLicenses(pkg),
		})
	}

	return components, nil
}

func shouldSkipSPDXPackage(pkg spdxPackage, documentNamePrefix string) bool {
	if strings.EqualFold(strings.TrimSpace(pkg.SPDXID), "SPDXRef-DOCUMENT") {
		return true
	}
	if documentNamePrefix == "" {
		return false
	}
	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return false
	}
	return strings.HasPrefix(name, documentNamePrefix)
}

func spdxPackagePURL(refs []spdxExternalRef) string {
	for _, ref := range refs {
		referenceType := strings.TrimSpace(ref.ReferenceType)
		referenceCategory := strings.TrimSpace(ref.ReferenceCategory)
		if !strings.EqualFold(referenceType, "purl") && !strings.EqualFold(referenceCategory, "PACKAGE-MANAGER") {
			continue
		}
		purl := strings.TrimSpace(ref.ReferenceLocator)
		if strings.HasPrefix(purl, "pkg:") {
			return purl
		}
	}
	return ""
}

// spdxLicenses extracts usable license identifiers; SPDX's NOASSERTION/NONE
// placeholders mean "unknown" and must not masquerade as licenses.
func spdxLicenses(pkg spdxPackage) []string {
	out := make([]string, 0, 2)
	for _, candidate := range []string{pkg.LicenseConcluded, pkg.LicenseDeclared} {
		value := strings.TrimSpace(candidate)
		upper := strings.ToUpper(value)
		if value == "" || upper == "NOASSERTION" || upper == "NONE" {
			continue
		}
		duplicate := false
		for _, existing := range out {
			if existing == value {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, value)
		}
	}
	return out
}
