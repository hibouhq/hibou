package depinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// SBOMs attached to an image (ADR-045 §10, C5). Three conventions carry
// them and a registry may hold any mix:
//
//   - OCI 1.1 referrers: manifests whose subject is the image, with the
//     SBOM as a layer (oras attach, cosign in OCI 1.1 mode);
//   - the cosign tag convention: <repo>:sha256-<digest>.sbom for a bare
//     SBOM layer and <repo>:sha256-<digest>.att for DSSE envelopes whose
//     payload is an in-toto statement with an SBOM predicate;
//   - BuildKit attestation manifests: entries of the multi-platform index
//     annotated vnd.docker.reference.type=attestation-manifest, whose
//     layers are in-toto statements (docker buildx --sbom).
//
// A signature is reported, never verified here: `hibou deps verify
// --key` does that with the key the user trusts.

// AttachedSBOM is one SBOM found next to an image.
type AttachedSBOM struct {
	// Source is referrers, cosign or buildkit.
	Source string `json:"source"`
	// Format is cyclonedx or spdx.
	Format        string `json:"format"`
	PredicateType string `json:"predicate_type,omitempty"`
	MediaType     string `json:"media_type,omitempty"`
	// Digest is the manifest that carries the SBOM.
	Digest string `json:"digest"`
	// Signed says a DSSE envelope with at least one signature carried the
	// statement; the signature is not verified by the scan.
	Signed bool `json:"signed"`
	// Components is what the SBOM declares; Added is what the filesystem
	// scan had not found and the SBOM contributed.
	Components int    `json:"components"`
	Added      int    `json:"added"`
	Document   []byte `json:"-"`
}

const (
	mediaTypeCycloneDX = "application/vnd.cyclonedx+json"
	mediaTypeSPDX      = "application/spdx+json"
	mediaTypeSPDXText  = "text/spdx+json"
	mediaTypeInToto    = "application/vnd.in-toto+json"
	mediaTypeDSSE      = "application/vnd.dsse.envelope.v1+json"

	buildkitReferenceType   = "vnd.docker.reference.type"
	buildkitReferenceDigest = "vnd.docker.reference.digest"
	buildkitAttestation     = "attestation-manifest"

	// maxAttachedSBOMBytes caps one attached document.
	maxAttachedSBOMBytes = 64 << 20
)

func sbomMediaType(mediaType string) bool {
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case mediaTypeCycloneDX, mediaTypeSPDX, mediaTypeSPDXText, mediaTypeInToto, mediaTypeDSSE:
		return true
	}
	return false
}

// attachedSBOMs looks for SBOMs through the three conventions. Registry
// errors are reported as warnings: a missing referrers endpoint or tag is
// the normal case, not a failure of the scan.
func attachedSBOMs(ctx context.Context, src *imageSource, imageDigest v1.Hash, warn func(string)) []AttachedSBOM {
	var out []AttachedSBOM
	seen := map[string]bool{}
	add := func(found []AttachedSBOM) {
		for _, sbom := range found {
			key := sbom.Source + "|" + sbom.Digest + "|" + sbom.PredicateType
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, sbom)
		}
	}
	repo := src.ref.Context()

	// OCI referrers; the library falls back to the referrers tag schema
	// when the registry predates the API.
	if index, err := remote.Referrers(repo.Digest(imageDigest.String()), src.opts...); err == nil {
		if manifest, err := index.IndexManifest(); err == nil {
			for _, desc := range manifest.Manifests {
				add(sbomsInManifest(ctx, src, repo.Digest(desc.Digest.String()), "referrers", warn))
			}
		}
	} else if !notFound(err) {
		warn(fmt.Sprintf("%s: referrers not readable: %v", src.ref, err))
	}

	// cosign tag convention.
	tagBase := "sha256-" + imageDigest.Hex
	for _, suffix := range []string{".sbom", ".att"} {
		tag := repo.Tag(tagBase + suffix)
		if _, err := remote.Head(tag, src.opts...); err != nil {
			if !notFound(err) {
				warn(fmt.Sprintf("%s: %s not readable: %v", src.ref, tag.TagStr(), err))
			}
			continue
		}
		add(sbomsInManifest(ctx, src, tag, "cosign", warn))
	}

	// BuildKit attestation manifests in the index.
	if src.index != nil {
		if manifest, err := src.index.IndexManifest(); err == nil {
			for _, desc := range manifest.Manifests {
				if desc.Annotations[buildkitReferenceType] != buildkitAttestation || desc.Annotations[buildkitReferenceDigest] != imageDigest.String() {
					continue
				}
				add(sbomsInManifest(ctx, src, repo.Digest(desc.Digest.String()), "buildkit", warn))
			}
		}
	}
	return out
}

// sbomsInManifest reads the layers of one manifest that carry an SBOM, a
// statement or an envelope.
func sbomsInManifest(_ context.Context, src *imageSource, ref name.Reference, source string, warn func(string)) []AttachedSBOM {
	img, err := remote.Image(ref, src.opts...)
	if err != nil {
		warn(fmt.Sprintf("%s: %v", ref, err))
		return nil
	}
	manifest, err := img.Manifest()
	if err != nil {
		warn(fmt.Sprintf("%s: %v", ref, err))
		return nil
	}
	digest, _ := img.Digest()
	var out []AttachedSBOM
	for _, layerDesc := range manifest.Layers {
		mediaType := string(layerDesc.MediaType)
		_, intoto := layerDesc.Annotations["in-toto.io/predicate-type"]
		_, cosign := layerDesc.Annotations["predicateType"]
		if !sbomMediaType(mediaType) && !intoto && !cosign {
			continue
		}
		if layerDesc.Size > maxAttachedSBOMBytes {
			warn(fmt.Sprintf("%s: attached document of %d bytes skipped (limit %d)", ref, layerDesc.Size, maxAttachedSBOMBytes))
			continue
		}
		layer, err := img.LayerByDigest(layerDesc.Digest)
		if err != nil {
			continue
		}
		rc, err := layer.Compressed()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxAttachedSBOMBytes+1))
		_ = rc.Close()
		if err != nil || len(data) > maxAttachedSBOMBytes {
			continue
		}
		sbom, ok := attachedFromBlob(data)
		if !ok {
			continue
		}
		sbom.Source, sbom.MediaType, sbom.Digest = source, mediaType, digest.String()
		if sbom.PredicateType == "" {
			sbom.PredicateType = firstNonEmptyString(layerDesc.Annotations["in-toto.io/predicate-type"], layerDesc.Annotations["predicateType"])
		}
		out = append(out, sbom)
	}
	return out
}

// attachedFromBlob reads a DSSE envelope, a bare in-toto statement or a
// bare SBOM document.
func attachedFromBlob(data []byte) (AttachedSBOM, bool) {
	if IsAttestation(data) {
		statement, envelope, err := ParseAttestation(data)
		if err != nil {
			return AttachedSBOM{}, false
		}
		document, format, err := statement.SBOM()
		if err != nil {
			return AttachedSBOM{}, false
		}
		return AttachedSBOM{Format: format, PredicateType: statement.PredicateType, Signed: envelope != nil && len(envelope.Signatures) > 0, Document: document}, true
	}
	format := sbomFormat(data)
	if format == "" {
		return AttachedSBOM{}, false
	}
	return AttachedSBOM{Format: format, Document: data}, true
}

// sbomFormat is cyclonedx, spdx or "" for data that is neither.
func sbomFormat(data []byte) string {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SpdxVersion string `json:"spdxVersion"`
	}
	if json.Unmarshal(data, &probe) != nil {
		return ""
	}
	switch {
	case strings.EqualFold(probe.BomFormat, "CycloneDX"):
		return "cyclonedx"
	case probe.SpdxVersion != "":
		return "spdx"
	}
	return ""
}

func notFound(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "404") || strings.Contains(message, "manifest_unknown") || strings.Contains(message, "name_unknown") || strings.Contains(message, "not found")
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
