package httpcatalog

import (
	"os"
	"testing"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// This package's tests use plain role names; tests of the environment rule
// set Environment or clear this themselves. Image prefixes lie under one
// example registry.
func TestMain(m *testing.M) {
	rolesWithoutEnvironment = true
	if err := imagerule.SetRegistry("registry.example.com/example-project/"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
