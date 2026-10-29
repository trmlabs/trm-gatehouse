package imagerule

import (
	"os"
	"testing"
)

const testRegistry = "registry.example.com/example-project/"

func TestMain(m *testing.M) {
	if err := SetRegistry(testRegistry); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

const (
	teamA     = "registry.example.com/example-project/example-images/team-a/"
	developer = "registry.example.com/example-project/example-developers-profile/"
	d1        = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2        = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func TestPrefixShape(t *testing.T) {
	for p, ok := range map[string]bool{
		teamA: true, developer: true,
		"registry.example.com/example-project/":                     false, // the whole project
		"registry.example.com/other-project/example-images/team-a/": false,
		"registry.example.com/example-project/repo/team-a/team/":    false, // deeper than one tenant
		"registry.example.com/example-project/repo/team-a":          false, // no trailing slash
		"other.example.com/example-project/repo/":                   false,
		"registry.example.com/example-project/Repo/":                false,
	} {
		if ValidPrefix(p) != ok {
			t.Errorf("%s: %v", p, !ok)
		}
	}
	if !Overlap(teamA, "registry.example.com/example-project/example-images/") || Overlap(teamA, developer) || !Overlap(teamA, teamA) {
		t.Error("overlap")
	}
}

func TestAllowedMatchesThePulledImage(t *testing.T) {
	for id, ok := range map[string]bool{
		"registry.example.com/example-project/example-images/team-a/agent@" + d2:    true,
		"registry.example.com/example-project/example-images/team-a/a/b@" + d2:      true,
		"registry.example.com/example-project/example-images/gatehouse/proxy@" + d2: false, // the proxy image is never an agent image
		"registry.example.com/example-project/example-images/team-ax/agent@" + d2:   false,
		"registry.example.com/example-project/example-images/team-a@" + d2:          false, // the prefix itself is no image
		"docker.io/library/busybox@" + d1:                                           true,  // an exact platform digest
		d1:                                                                          true,
		"docker.io/library/busybox@" + d2:                                           false,
		"registry.example.com/example-project/example-images/team-a/agent:latest":   false, // a tag, not a pull
		"": false,
		// Components outside the OCI grammar never parse, so none can climb
		// out of the prefix or pad it.
		"registry.example.com/example-project/example-images/team-a/../gatehouse/proxy@" + d2:      false,
		"registry.example.com/example-project/example-images/team-a/./agent@" + d2:                 false,
		"registry.example.com/example-project/example-images/team-a//agent@" + d2:                  false,
		"registry.example.com/example-project/example-images/team-a/agent/@" + d2:                  false,
		"registry.example.com/example-project/example-images/team-a/-agent@" + d2:                  false,
		"registry.example.com/example-project/example-images/team-a/my_tool.v2@" + d2:              true,
		"localhost:5000/team-a/agent@" + d2:                                                        false,
		"docker-pullable://registry.example.com/example-project/example-images/team-a/agent@" + d2: true,
	} {
		if Allowed(id, teamA, []string{d1}) != ok {
			t.Errorf("%s: %v", id, !ok)
		}
	}
	if Allowed("registry.example.com/example-project/example-developers-profile/x@"+d2, "", []string{d1}) {
		t.Error("no prefix still matched a repository")
	}
}

func TestRegistry(t *testing.T) {
	t.Cleanup(func() { _ = SetRegistry(testRegistry) })
	// teamA has dots, which the prefix shape refuses with or without a
	// registry; repo/tenant/ has the shape, so only the unset registry
	// refuses it.
	if err := SetRegistry(""); err != nil || ValidPrefix(teamA) || ValidPrefix("repo/tenant/") {
		t.Fatalf("no registry still admitted a prefix: %v", err)
	}
	for _, r := range []string{
		"registry.example.com",                       // no path
		"registry.example.com/example-project",       // no trailing slash
		"localhost/example-project/",                 // no dotted host
		"registry.example.com:5000/example-project/", // a port
		"registry.example.com/Example-Project/",
		"registry.example.com//",
		"https://registry.example.com/example-project/",
	} {
		if SetRegistry(r) == nil {
			t.Errorf("%s: accepted", r)
		}
	}
	if Registry() != "" {
		t.Fatalf("a refused registry was kept: %q", Registry())
	}
	if err := SetRegistry("other.example.com/team/images/"); err != nil {
		t.Fatal(err)
	}
	if !ValidPrefix("other.example.com/team/images/agents/") || ValidPrefix(teamA) {
		t.Error("prefixes judged against the wrong registry")
	}
}
