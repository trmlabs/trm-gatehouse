package workloadidentity

import (
	"os"
	"testing"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// Image prefixes in this package's tests lie under one example registry.
func TestMain(m *testing.M) {
	if err := imagerule.SetRegistry("registry.example.com/example-project/"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
