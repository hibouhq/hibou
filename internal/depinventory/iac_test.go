package depinventory

import (
	"context"
	"testing"
)

func TestExtractIaC(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "infra/.terraform.lock.hcl", `provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:abc=",
  ]
}
`)
	writeFile(t, root, "charts/app/Chart.lock", "dependencies:\n- name: postgresql\n  repository: https://charts.bitnami.com/bitnami\n  version: 13.2.24\n")
	writeFile(t, root, ".github/workflows/ci.yml", "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@0a12ed9d6a96ab950c8f026ed9f722fe0da7ef32\n      - uses: ./.github/actions/local\n")
	writeFile(t, root, ".gitlab-ci.yml", "include:\n  - project: platform/ci-templates\n    ref: v2.1.0\n    file: /go.yml\n  - component: gitlab.example.com/platform/sast@1.2.0\n")
	writeFile(t, root, "ansible/requirements.yml", "collections:\n  - name: community.general\n    version: 8.0.0\nroles:\n  - geerlingguy.docker\n")
	writeFile(t, root, "Dockerfile", "FROM golang:1.22 AS build\nRUN go build\nFROM gcr.io/distroless/static@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nCOPY --from=build /app /app\n")
	writeFile(t, root, "docker-compose.yml", "services:\n  db:\n    image: postgres:16\n  app:\n    image: ${IMAGE}\n")

	inv, err := Extract(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	byEco := map[string][]Component{}
	for _, c := range inv.Components {
		byEco[c.Ecosystem] = append(byEco[c.Ecosystem], c)
	}
	if tf := byEco[EcosystemTerraform]; len(tf) != 1 || tf[0].Version != "5.31.0" || tf[0].Resolution != ResolutionRecorded || tf[0].Name != "hashicorp/aws" {
		t.Errorf("terraform: %+v", tf)
	}
	if helm := byEco[EcosystemHelm]; len(helm) != 1 || helm[0].Version != "13.2.24" {
		t.Errorf("helm: %+v", helm)
	}
	actions := byEco[EcosystemGitHubActions]
	if len(actions) != 2 {
		t.Fatalf("actions: %+v", actions)
	}
	for _, a := range actions {
		switch a.Name {
		case "actions/checkout":
			if a.Resolution != ResolutionDeclared || a.Version != "v4" {
				t.Errorf("checkout by tag must be declared: %+v", a)
			}
		case "actions/setup-go":
			if a.Resolution != ResolutionRecorded {
				t.Errorf("setup-go by SHA must be recorded: %+v", a)
			}
		}
	}
	if gl := byEco[EcosystemGitLabCI]; len(gl) != 2 {
		t.Errorf("gitlab: %+v", gl)
	}
	if an := byEco[EcosystemAnsible]; len(an) != 2 {
		t.Errorf("ansible: %+v", an)
	}
	oci := byEco[EcosystemOCI]
	if len(oci) != 3 {
		t.Fatalf("oci: %+v", oci)
	}
	for _, c := range oci {
		if c.Name == "gcr.io/distroless/static" && c.Resolution != ResolutionRecorded {
			t.Errorf("digest-pinned image must be recorded: %+v", c)
		}
		if c.Name == "golang" && (c.Version != "1.22" || c.Resolution != ResolutionDeclared) {
			t.Errorf("tagged image: %+v", c)
		}
	}
}
