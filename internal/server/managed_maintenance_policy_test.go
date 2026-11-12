package server

import (
	"encoding/json"
	"testing"

	"github.com/hibouhq/hibou/internal/store"
)

func TestManagedMaintenanceMappingUsesExplicitTagPattern(t *testing.T) {
	settings := managedMaintenanceSettings{Mappings: []managedMaintenanceMapping{{ID: "line-1", TagPattern: "v1.2.*", TargetTemplate: "release/{major}.{minor}"}}}
	if err := settings.validate(); err != nil {
		t.Fatal(err)
	}
	mapping := settings.Mappings[0]
	target, matched, err := mapping.target("v1.2.3")
	if err != nil || !matched || target != "release/1.2" {
		t.Fatalf("explicit mapping: %q %v %v", target, matched, err)
	}
	if _, matched, err := mapping.target("v2.0.0"); err != nil || matched {
		t.Fatalf("unmapped line was guessed: %v %v", matched, err)
	}
	for _, template := range []string{"release/{unknown}", "../main", "release/.hidden", "release/main.lock"} {
		bad := managedMaintenanceSettings{Mappings: []managedMaintenanceMapping{{ID: "bad", TagPattern: "*", TargetTemplate: template}}}
		if bad.validate() == nil {
			t.Fatalf("unsafe template accepted: %s", template)
		}
	}
}

func TestManagedMaintenanceMappingDoesNotUseDependencyInventoryBranches(t *testing.T) {
	org := &store.Organization{Settings: json.RawMessage(`{"dependencies":{"branches":["release/*"]},"dependency_branches":["main","release/*"]}`)}
	settings, err := parseManagedMaintenanceSettings(org)
	if err != nil || settings.AllowCreation || len(settings.Mappings) != 0 {
		t.Fatalf("inventory policy became maintenance mapping: %v %v", settings, err)
	}
}
