package depinventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	layerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/trace"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Container images (ADR-045 §10, C2, C3 and C5): OS packages and language
// packages of every layer, each attributed to the layer that introduced
// it, with the base image told apart from the application layers, plus
// the SBOMs the registry holds for the image.

// ImageInventory is a scanned image.
type ImageInventory struct {
	Reference string            `json:"reference"`
	Digest    string            `json:"digest,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	// BaseImage is what the image says it was built on
	// (org.opencontainers.image.base.name), when the builder recorded it.
	BaseImage string `json:"base_image,omitempty"`
	// Layers is the image's history with the components each layer
	// introduced. BaseImage marks the layers the heuristic attributes to
	// the base image: everything up to the last CMD or ENTRYPOINT before
	// the application's own layers.
	Layers []LayerSummary `json:"layers"`
	// AttachedSBOMs are the SBOMs found next to the image in its registry
	// (C5): OCI referrers, the cosign tag convention, BuildKit attestation
	// manifests. Their components join the inventory when the filesystem
	// scan did not find them.
	AttachedSBOMs []AttachedSBOM     `json:"attached_sboms,omitempty"`
	Inventory     *ArtifactInventory `json:"inventory"`
}

// LayerSummary is one entry of the image history.
type LayerSummary struct {
	Index      int    `json:"index"`
	DiffID     string `json:"diff_id,omitempty"`
	Command    string `json:"command,omitempty"`
	Empty      bool   `json:"empty,omitempty"`
	BaseImage  bool   `json:"base_image"`
	Components int    `json:"components"`
}

// imageSource is an opened image with what is needed to look around it.
type imageSource struct {
	img v1.Image
	// ref and opts are set for registry references; a tarball has neither
	// a registry nor attached SBOMs.
	ref  name.Reference
	opts []remote.Option
	// index is the multi-platform index the reference resolved through,
	// which is where BuildKit stores attestations.
	index v1.ImageIndex
}

func openImage(ctx context.Context, reference string) (*imageSource, error) {
	if info, statErr := os.Stat(reference); statErr == nil && !info.IsDir() {
		img, err := tarball.ImageFromPath(reference, nil)
		if err != nil {
			return nil, fmt.Errorf("read image tarball: %w", err)
		}
		return &imageSource{img: img}, nil
	}
	ref, err := name.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx)}
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", reference, err)
	}
	src := &imageSource{ref: ref, opts: opts}
	if desc.MediaType.IsIndex() {
		if index, err := desc.ImageIndex(); err == nil {
			src.index = index
		}
	}
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", reference, err)
	}
	src.img = img
	return src, nil
}

// ScanImage analyses a container image: a local tarball (docker save,
// OCI layout tar) or a registry reference pulled with the user's own
// credentials. Every component is attributed to the layer that introduced
// it (ADR-045 §10); for a registry reference the SBOMs attached to the
// image are read as well, unless opts.SkipAttachedSBOMs.
func ScanImage(ctx context.Context, reference string, opts ScanOptions) (*ImageInventory, error) {
	opts = opts.withDefaults()
	src, err := openImage(ctx, reference)
	if err != nil {
		return nil, err
	}
	out := &ImageInventory{Reference: reference, Layers: []LayerSummary{}}
	var imageDigest v1.Hash
	if digest, err := src.img.Digest(); err == nil {
		imageDigest = digest
		out.Digest = digest.String()
	}
	if config, err := src.img.ConfigFile(); err == nil && config != nil {
		out.Labels = config.Config.Labels
		out.BaseImage = strings.TrimSpace(config.Config.Labels["org.opencontainers.image.base.name"])
	}

	layered, err := layerimage.FromV1Image(src.img, layerimage.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("unpack image: %w", err)
	}
	defer func() { _ = layered.CleanUp() }()
	chain, err := layered.ChainLayers()
	if err != nil {
		return nil, fmt.Errorf("read image layers: %w", err)
	}
	components, unidentified, err := extractImageArtifacts(ctx, layered, chain, opts)
	if err != nil {
		return nil, err
	}
	perLayer := map[int]int{}
	for i := range components {
		components[i].Path = reference + "!/" + components[i].Path
		components[i].Module = reference
		if components[i].Layer != nil {
			perLayer[components[i].Layer.Index]++
		}
	}
	for _, layer := range chain {
		summary := LayerSummary{Index: layer.Index(), Components: perLayer[layer.Index()], BaseImage: inBaseImage(layered, layer.Index())}
		if latest := layer.Layer(); latest != nil {
			summary.DiffID = latest.DiffID().String()
			summary.Command = strings.TrimSpace(latest.Command())
			summary.Empty = latest.IsEmpty()
		}
		out.Layers = append(out.Layers, summary)
	}

	inv := &ArtifactInventory{Components: components, Unidentified: []Unidentified{}}
	inv.Targets = []TargetSummary{{Path: reference, Kind: KindImage, Components: len(components), SHA256: strings.TrimPrefix(out.Digest, "sha256:"), Metadata: imageMetadata(out.Labels)}}

	// C5: what the registry holds next to the image. The filesystem scan
	// is the higher resolution, so an attached SBOM only adds what the
	// scan did not see (a shaded jar, a minified bundle, a stripped
	// binary) and is listed as its own source.
	if src.ref != nil && !opts.SkipAttachedSBOMs && imageDigest.Hex != "" {
		known := make(map[string]bool, len(inv.Components))
		for _, c := range inv.Components {
			known[c.Purl] = true
		}
		out.AttachedSBOMs = attachedSBOMs(ctx, src, imageDigest, opts.Warn)
		for i := range out.AttachedSBOMs {
			attached := &out.AttachedSBOMs[i]
			label := fmt.Sprintf("%s!sbom/%s/%s", reference, attached.Source, shortHex(attached.Digest))
			parsed, err := componentsFromSBOM(attached.Document, label)
			if err != nil {
				opts.Warn(fmt.Sprintf("%s: attached %s SBOM (%s) not readable: %v", reference, attached.Format, attached.Source, err))
				continue
			}
			attached.Components = len(parsed)
			for _, c := range parsed {
				if known[c.Purl] {
					continue
				}
				known[c.Purl] = true
				c.Module = reference
				inv.Components = append(inv.Components, c)
				attached.Added++
			}
			inv.Targets = append(inv.Targets, TargetSummary{
				Path: label, Kind: KindSBOM, Components: attached.Added, SHA256: shortHex(attached.Digest),
				Metadata: map[string]string{"attached_sbom": attached.Source, "format": attached.Format, "predicate_type": attached.PredicateType},
			})
		}
	}

	inv.Components = dedupeComponents(inv.Components)
	sortComponents(inv.Components)
	inv.addUnidentified(unidentified, opts)
	inv.Modules = buildModules(inv.Components)
	out.Inventory = inv
	return out, nil
}

// extractImageArtifacts runs the artifact extractors over the image's
// chain filesystem, traces every package back to the layer that
// introduced it, and lists what no extractor recognised.
func extractImageArtifacts(ctx context.Context, layered *layerimage.Image, chain []scalibrimage.ChainLayer, opts ScanOptions) ([]Component, []Unidentified, error) {
	fsys := layered.FS()
	packages, extractors, cfg, err := runArtifactExtractors(ctx, []*scalibrfs.ScanRoot{{FS: fsys}})
	if err != nil {
		return nil, nil, err
	}
	// PopulateLayerDetails re-runs each package's extractor on older
	// layers to find where it first appeared; it rewrites the config it
	// is given, so it gets a copy.
	traceCfg := *cfg
	trace.PopulateLayerDetails(ctx, &packages, chain, extractors, &traceCfg)
	components, identified := componentsFromPackages(packages.Packages)
	for i := range components {
		if components[i].Layer != nil {
			components[i].Layer.BaseImage = inBaseImage(layered, components[i].Layer.Index)
		}
	}
	var unidentified []Unidentified
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d == nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel := strings.TrimPrefix(p, "./")
		if identified[rel] || IsManifestPath(rel) {
			return nil
		}
		kind := fileTypeOf(rel, func() bool { return isBinaryReader(fsys, p) })
		if kind == "" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		unidentified = append(unidentified, Unidentified{Path: rel, Size: info.Size(), Type: kind})
		return nil
	})
	if opts.JarLookup != nil {
		found, rest := identifyJars(ctx, fsys, unidentified, opts)
		components = append(components, found...)
		unidentified = rest
	}
	return components, unidentified, nil
}

// inBaseImage applies the engine's heuristic: the base image ends at the
// last CMD or ENTRYPOINT before the application's own layers. Without a
// usable history nothing is attributed.
func inBaseImage(layered *layerimage.Image, index int) bool {
	return layered != nil && layered.BaseImageIndex >= 0 && index <= layered.BaseImageIndex
}

func isBinaryReader(fsys fs.FS, p string) bool {
	f, err := fsys.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	return hasBinaryMagic(head[:n])
}

func imageMetadata(labels map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range labels {
		switch key {
		case "org.opencontainers.image.revision":
			out["revision"] = value
		case "org.opencontainers.image.version":
			out["version"] = value
		case "org.opencontainers.image.source":
			out["source"] = value
		case "org.opencontainers.image.base.name":
			out["base_image"] = value
		case "org.opencontainers.image.base.digest":
			out["base_image_digest"] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func shortHex(digest string) string {
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}
