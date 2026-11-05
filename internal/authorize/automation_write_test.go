package authorize

import (
	"context"
	"testing"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// writeCatalog lists a git, a github-api and a header entry for three Automations: auto-1 names the two GitHub entries in write, auto-2 has an empty write list, auto-3 has no write key.
func writeCatalog(t *testing.T) httpcatalog.Catalog {
	t.Helper()
	c, err := httpcatalog.Parse([]byte(`{
		"pools":[{"name":"automations","namespace":"cursor","serviceAccount":"worker","identity":"cursor-automation"}],
		"entries":[
		 {"name":"repo-git","host":"github.com","kind":"git","pools":["automations"],"git":{"appID":7,"installationID":42,"repos":[
		  {"repo":"example-org/example-app","access":"write","refPrefixes":["refs/heads/factory/"]}]}},
		 {"name":"repo-api","host":"api.github.com","kind":"github-api","pools":["automations"],"git":{"appID":7,"installationID":42,"repos":[
		  {"repo":"example-org/example-app","access":"write","operations":["pr.read","pr.comment"],"poolOperations":{"automations":["pr.read","pr.comment"]}}]}},
		 {"name":"tracker","host":"api.tracker.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",
		  "placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["automations"]}],
		"automations":[
		 {"id":"auto-1","name":"explorer","owner":"platform-team","entries":["repo-git","repo-api","tracker"],"write":["repo-git","repo-api"]},
		 {"id":"auto-2","name":"auditor","owner":"platform-team","entries":["repo-git","repo-api","tracker"],"write":[]},
		 {"id":"auto-3","name":"unkeyed","owner":"platform-team","entries":["repo-git","repo-api","tracker"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// An Automation with a write list holds the write grant only on the entries it names, none for an empty list.
// One with no write key, and everyone else, keep the pool's grant; a requester claiming to be an Automation with no block holds none.
func TestMayWriteFollowsTheAutomationsBlock(t *testing.T) {
	ctx := context.Background()
	pool, _ := writeCatalog(t).Pool("automations")
	for token, want := range map[string]map[string]bool{
		"explorer": {"repo-git": true, "repo-api": true, "tracker": false, "unlisted": false},
		"auditor":  {"repo-git": false, "repo-api": false, "tracker": false, "unlisted": false},
		"reader":   {"repo-git": true, "repo-api": true, "tracker": true, "unlisted": true},
	} {
		run := automationRuns[token]
		who, refusal := Resolve(ctx, pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" || who.Kind != "automation" {
			t.Fatalf("%s: %q %+v", token, refusal, who)
		}
		for entry, allowed := range want {
			if who.MayWrite(entry) != allowed {
				t.Errorf("%s on %s: MayWrite %v, want %v", token, entry, who.MayWrite(entry), allowed)
			}
		}
	}

	who, refusal := Resolve(ctx, cursorPool, "alice-1", Claims{Pod: "pod-b", ClaimedRun: "bc-1"}, runs, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "person" || !who.MayWrite("repo-git") || !who.MayWrite("repo-api") {
		t.Errorf("person: %q %+v", refusal, who)
	}
	// An Automation's run served as its person (opted-in person pool) has that person's access.
	optedIn := httpcatalog.Pool{Identity: "cursor-session", AutomationRunsAsPerson: true}
	who, refusal = Resolve(ctx, optedIn, "auditor", Claims{Pod: "pod-c", ClaimedRun: "bc-2"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "person" || !who.MayWrite("repo-git") {
		t.Errorf("Automation run as its person: %q %+v", refusal, who)
	}
	if !(Requester{}).MayWrite("repo-git") || !(Requester{Kind: "agent"}).MayWrite("repo-git") {
		t.Error("a requester that is no Automation lost the pool's grant")
	}
	if (Requester{Kind: "automation", Subject: "auto-1"}).MayWrite("repo-git") {
		t.Error("an Automation with no block holds a write grant")
	}
}
