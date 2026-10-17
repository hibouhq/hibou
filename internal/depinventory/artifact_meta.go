package depinventory

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func sha256Of(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// deliverableMetadata reads what a deliverable says about itself, for the
// plausibility checks of ADR-046 §4.3: a Go binary's module version and
// VCS revision, a JAR's Implementation-Version and main pom.properties
// version, an npm tarball's or wheel's package version.
func deliverableMetadata(target, unpackedRoot string) map[string]string {
	out := map[string]string{}
	switch {
	case isBinary(target):
		if info, err := buildinfo.ReadFile(target); err == nil {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				out["version"] = info.Main.Version
			}
			out["module"] = info.Main.Path
			out["go"] = info.GoVersion
			for _, setting := range info.Settings {
				switch setting.Key {
				case "vcs.revision":
					out["revision"] = setting.Value
				case "vcs.modified":
					out["modified"] = setting.Value
				}
			}
		}
	case javaArchiveExtensions[extensionOf(target)]:
		for key, value := range jarMetadata(target) {
			out[key] = value
		}
	default:
		// An unpacked archive: npm tarball (package/package.json), wheel or
		// sdist (*.dist-info/METADATA, PKG-INFO), a jar inside.
		_ = filepath.WalkDir(unpackedRoot, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || len(out) > 0 {
				return nil
			}
			base := filepath.Base(p)
			switch {
			case base == "package.json" && !strings.Contains(filepath.ToSlash(p), "node_modules/"):
				var pkg struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				}
				if data, readErr := os.ReadFile(p); readErr == nil && json.Unmarshal(data, &pkg) == nil && pkg.Version != "" { // #nosec G304 G122 -- inside the temp root this process unpacked without symlinks
					out["name"], out["version"] = pkg.Name, pkg.Version
				}
			case base == "METADATA" || base == "PKG-INFO":
				if f, openErr := os.Open(p); openErr == nil { // #nosec G304 G122 -- inside the temp root this process unpacked without symlinks
					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						line := scanner.Text()
						if strings.HasPrefix(line, "Version: ") {
							out["version"] = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
						}
						if strings.HasPrefix(line, "Name: ") {
							out["name"] = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
						}
						if line == "" {
							break
						}
					}
					_ = f.Close()
				}
			}
			return nil
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// jarMetadata reads META-INF/MANIFEST.MF and the main pom.properties.
func jarMetadata(target string) map[string]string {
	out := map[string]string{}
	reader, err := zip.OpenReader(target)
	if err != nil {
		return nil
	}
	defer reader.Close()
	var pomProperties []*zip.File
	for _, file := range reader.File {
		switch {
		case file.Name == "META-INF/MANIFEST.MF":
			rc, err := file.Open()
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				for _, key := range []string{"Implementation-Version", "Implementation-Title", "Bundle-Version", "Start-Class"} {
					if strings.HasPrefix(line, key+": ") {
						out[strings.ToLower(strings.ReplaceAll(key, "-", "_"))] = strings.TrimSpace(strings.TrimPrefix(line, key+": "))
					}
				}
			}
			_ = rc.Close()
		case strings.HasPrefix(file.Name, "META-INF/maven/") && strings.HasSuffix(file.Name, "/pom.properties"):
			pomProperties = append(pomProperties, file)
		}
	}
	// The main artifact's pom.properties is the one not nested in a lib
	// jar; a fat jar carries only its own at the top level.
	for _, file := range pomProperties {
		rc, err := file.Open()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(rc)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "version=") {
				out["pom_version"] = strings.TrimPrefix(line, "version=")
			}
			if strings.HasPrefix(line, "artifactId=") {
				out["artifact_id"] = strings.TrimPrefix(line, "artifactId=")
			}
		}
		_ = rc.Close()
		break
	}
	if v, ok := out["implementation_version"]; ok && out["version"] == "" {
		out["version"] = v
	} else if v, ok := out["pom_version"]; ok && out["version"] == "" {
		out["version"] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
