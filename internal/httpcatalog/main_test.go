package httpcatalog

import (
	"os"
	"testing"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// Tests use plain role names; tests of the environment rule set Environment or clear this themselves.
func TestMain(m *testing.M) {
	rolesWithoutEnvironment = true
	if err := imagerule.SetRegistry("registry.example.com/example-project/"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
