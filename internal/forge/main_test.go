package forge

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Every GitHub call the tests exercise must declare its permissions.
	requireDeclaredScopes = true
	os.Exit(m.Run())
}
