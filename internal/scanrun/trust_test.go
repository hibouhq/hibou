package scanrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanplan"
)

func trustCatalog() *scancatalog.Catalog {
	return &scancatalog.Catalog{SchemaVersion: 1, Revision: "embedded.1", Scanners: []scancatalog.Scanner{
		{
			ID: "grep", Name: "Grep", Engine: "opengrep", EngineVersion: "1.0", AdapterVersion: "1",
			ExitCodes: map[string]string{"0": "ok", "1": "findings", "default": "error"},
			Command:   scancatalog.Command{Args: []string{"scan", "--sarif-output={sarif}", "-f", "{rules}", "{targets}"}},
			Distributions: []scancatalog.Distribution{
				{Kind: "binary", OS: "linux", Arch: "amd64", Asset: "grep_linux_x86", URL: "https://example.test/grep_linux_x86", SHA256: digestOf([]byte("linux-amd64"))},
				{Kind: "binary", OS: "darwin", Arch: "arm64", Asset: "grep_osx_arm64", URL: "https://example.test/grep_osx_arm64", SHA256: digestOf([]byte("darwin-arm64"))},
			},
		},
		{
			ID: "bugs", Name: "Bugs", Engine: "spotbugs", EngineVersion: "4.0", AdapterVersion: "1",
			Distributions: []scancatalog.Distribution{
				{Kind: "maven", Coordinates: "com.github.spotbugs:spotbugs-maven-plugin:4.0.0", URL: "https://repo1.maven.org/maven2/com/github/spotbugs/spotbugs-maven-plugin/4.0.0/spotbugs-maven-plugin-4.0.0.jar", SHA256: digestOf([]byte("plugin"))},
				{Kind: "maven", Coordinates: "com.h3xstream.findsecbugs:findsecbugs-plugin:1.0", URL: "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/1.0/findsecbugs-plugin-1.0.jar", SHA256: digestOf([]byte("fsb"))},
			},
		},
	}}
}

func linuxResolver() Resolver {
	return Resolver{Catalog: trustCatalog(), GOOS: "linux", GOARCH: "amd64"}
}

// P1: what runs comes from the embedded catalog. A server that sends its
// own engine, command, coordinates or a different binary is ignored or
// refused; only the download URL is taken.
func TestResolveTakesIdentityFromEmbeddedCatalog(t *testing.T) {
	served := &CatalogEntry{Scanner: scancatalog.Scanner{ID: "grep", Engine: "spotbugs", EngineVersion: "1.0",
		Command: scancatalog.Command{Args: []string{"--config", "https://evil.example/rules", "{targets}"}}}}
	job := scanplan.Job{ID: "grep-1", ScannerID: "grep", Targets: []string{"src"}, Command: []string{"sh", "-c", "id"},
		Artifact: &scancatalog.Location{URL: "https://mirror.example/grep_linux_x86", SHA256: digestOf([]byte("linux-amd64")), Source: "mirror"}}

	trusted, entry, err := linuxResolver().Resolve(job, served)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Engine != "opengrep" || strings.Join(entry.Command.Args, " ") != "scan --sarif-output={sarif} -f {rules} {targets}" {
		t.Fatalf("engine/args must be embedded: %s %v", entry.Engine, entry.Command.Args)
	}
	if strings.Join(trusted.Command, " ") == "sh -c id" {
		t.Fatal("the server's command must not survive")
	}
	if trusted.Artifact.URL != "https://mirror.example/grep_linux_x86" || trusted.Artifact.SHA256 != digestOf([]byte("linux-amd64")) {
		t.Fatalf("artifact = %+v", trusted.Artifact)
	}
}

func TestResolveRefusesWhatTheCLIDoesNotPin(t *testing.T) {
	linux := digestOf([]byte("linux-amd64"))
	artifact := func(digest string) *scancatalog.Location {
		return &scancatalog.Location{URL: "https://example.test/x", SHA256: digest}
	}
	cases := []struct {
		name   string
		job    scanplan.Job
		served *CatalogEntry
		want   string
	}{
		{"unknown scanner", scanplan.Job{ScannerID: "newtool", Artifact: artifact(linux)}, nil, "upgrade the hibou CLI"},
		{"newer version", scanplan.Job{ScannerID: "grep", Artifact: artifact(linux)}, &CatalogEntry{Scanner: scancatalog.Scanner{ID: "grep", EngineVersion: "2.0"}}, "upgrade the hibou CLI"},
		{"unpinned digest", scanplan.Job{ScannerID: "grep", Artifact: artifact(digestOf([]byte("evil")))}, nil, "upgrade the hibou CLI"},
		{"bad digest", scanplan.Job{ScannerID: "grep", Artifact: artifact("../../etc/passwd")}, nil, "64 lowercase hex"},
		{"other platform", scanplan.Job{ScannerID: "grep", Artifact: artifact(digestOf([]byte("darwin-arm64")))}, nil, "this runner is linux/amd64"},
		{"plain http", scanplan.Job{ScannerID: "grep", Artifact: &scancatalog.Location{URL: "http://example.test/x", SHA256: linux}}, nil, "not allowed"},
		{"file without bundle", scanplan.Job{ScannerID: "grep", Artifact: &scancatalog.Location{URL: "file:///etc/x", SHA256: linux}}, nil, "--bundle-dir"},
		{"option target", scanplan.Job{ScannerID: "grep", Targets: []string{"--exclude=*"}, Artifact: artifact(linux)}, nil, "starts with '-'"},
		{"escaping target", scanplan.Job{ScannerID: "grep", Targets: []string{"src/../../etc"}, Artifact: artifact(linux)}, nil, "'..'"},
		{"absolute target", scanplan.Job{ScannerID: "grep", Targets: []string{"/etc"}, Artifact: artifact(linux)}, nil, "absolute"},
		{"option exclusion", scanplan.Job{ScannerID: "grep", Targets: []string{"."}, Exclusions: []string{"-x"}, Artifact: artifact(linux)}, nil, "starts with '-'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := linuxResolver().Resolve(tc.job, tc.served)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resolve = %v, want %q", err, tc.want)
			}
		})
	}
}

// An offline location is re-derived under the runner's bundle directory:
// the server's file path is never used.
func TestResolveRederivesOfflineLocation(t *testing.T) {
	resolver := linuxResolver()
	resolver.BundleDir = "/opt/hibou-bundle"
	job := scanplan.Job{ScannerID: "grep", Targets: []string{"."},
		Artifact: &scancatalog.Location{URL: "file:///home/runner/.ssh/id_rsa", SHA256: digestOf([]byte("linux-amd64")), Source: "bundle"}}
	trusted, _, err := resolver.Resolve(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.Artifact.URL != "file:///opt/hibou-bundle/grep/1.0/grep_linux_x86" {
		t.Fatalf("offline location = %s", trusted.Artifact.URL)
	}
}

// Maven distributions: coordinates and pins come from the embedded catalog,
// the server's location is matched by sha256; a served distribution the CLI
// does not pin is ignored.
func TestResolveMavenLocations(t *testing.T) {
	fsb := digestOf([]byte("fsb"))
	served := &CatalogEntry{Scanner: scancatalog.Scanner{ID: "bugs", EngineVersion: "4.0"}, Distributions: []ResolvedDistribution{
		{Distribution: scancatalog.Distribution{Kind: "maven", Coordinates: "evil:evil:1", SHA256: fsb},
			Location: &scancatalog.Location{URL: "https://maven.mirror.example/fsb.jar", SHA256: fsb}},
		{Distribution: scancatalog.Distribution{Kind: "maven", Coordinates: "x:y:1", SHA256: digestOf([]byte("other"))},
			Location: &scancatalog.Location{URL: "https://evil.example/other.jar", SHA256: digestOf([]byte("other"))}},
	}}
	job := scanplan.Job{ScannerID: "bugs", Targets: []string{"java"},
		Artifact: &scancatalog.Location{URL: "https://maven.mirror.example/plugin.jar", SHA256: digestOf([]byte("plugin"))}}
	_, entry, err := linuxResolver().Resolve(job, served)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Distributions) != 2 {
		t.Fatalf("distributions = %+v", entry.Distributions)
	}
	for _, d := range entry.Distributions {
		if strings.Contains(d.Coordinates, "evil") {
			t.Fatalf("server coordinates used: %s", d.Coordinates)
		}
		if strings.Contains(d.Coordinates, "findsecbugs") && (d.Location == nil || d.Location.URL != "https://maven.mirror.example/fsb.jar") {
			t.Fatalf("findsecbugs location = %+v", d.Location)
		}
		if strings.Contains(d.Coordinates, "maven-plugin") && d.Location != nil {
			t.Fatalf("no served location for the plugin, got %+v", d.Location)
		}
	}
}

func TestMavenJarPathRejectsMalformedCoordinates(t *testing.T) {
	for _, coordinates := range []string{"", "a", "a:b", "a:b:c:d", "::", "a:..:1", "a/b:c:1", "..:c:1", "a:-b:1"} {
		if _, err := mavenJarPath("/repo", coordinates); err == nil {
			t.Errorf("mavenJarPath(%q) accepted", coordinates)
		}
	}
	got, err := mavenJarPath("/repo", "com.example:tool:1.2")
	if err != nil || got != filepath.Join("/repo", "com", "example", "tool", "1.2", "tool-1.2.jar") {
		t.Fatalf("mavenJarPath = %s, %v", got, err)
	}
}

// A module directory that is a link out of the checkout is refused before
// mvn runs in it.
func TestSpotBugsModuleMustStayUnderSourceRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	_ = os.MkdirAll(filepath.Join(outside, "target", "classes"), 0o750)
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := withinRoot(root, "escape"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlinked module = %v", err)
	}
	if _, err := withinRoot(root, "../x"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("dot-dot module = %v", err)
	}
	if dir, err := withinRoot(root, "."); err != nil || dir != root {
		t.Fatalf("root module = %s, %v", dir, err)
	}

	jar := []byte("findsecbugs")
	bundle := t.TempDir()
	_ = os.WriteFile(filepath.Join(bundle, "fsb.jar"), jar, 0o600)
	entry := CatalogEntry{Scanner: scancatalog.Scanner{Engine: "spotbugs"}, Distributions: []ResolvedDistribution{
		{Distribution: scancatalog.Distribution{Kind: "maven", Coordinates: "com.github.spotbugs:spotbugs-maven-plugin:4.9.3.0"}},
		{Distribution: scancatalog.Distribution{Kind: "maven", Coordinates: "com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0"},
			Location: &scancatalog.Location{URL: "file://" + filepath.ToSlash(filepath.Join(bundle, "fsb.jar")), SHA256: digestOf(jar)}},
	}}
	env := Environment{SourceRoot: root, OutDir: t.TempDir(), Fetcher: &Fetcher{CacheDir: t.TempDir(), BundleDir: bundle},
		Command: func(context.Context, string, string, ...string) ([]byte, int, error) {
			t.Fatal("mvn must not run outside the source root")
			return nil, 0, nil
		}}
	if _, err := Run(context.Background(), scanplan.Job{ID: "sb", Targets: []string{"escape"}}, entry, env); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Run = %v", err)
	}
}

// The CLI and the planner share one validator (planpath): backslashes and
// drive letters are refused here exactly as the server refuses to plan them.
func TestValidatePlanPathsSharedValidator(t *testing.T) {
	t.Parallel()

	if err := ValidatePlanPaths([]string{".", "java", "web/app"}, []string{"node_modules"}); err != nil {
		t.Fatalf("safe paths refused: %v", err)
	}
	for _, unsafe := range []string{`a\..\..\etc`, `a\b`, "C:/Windows", "/etc", "-x", "a/../b", ""} {
		if err := ValidatePlanPaths([]string{unsafe}, nil); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("target %q = %v, want ErrUnsafePath", unsafe, err)
		}
		if err := ValidatePlanPaths(nil, []string{unsafe}); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("exclusion %q = %v, want ErrUnsafePath", unsafe, err)
		}
	}
}
