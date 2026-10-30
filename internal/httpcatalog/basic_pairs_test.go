package httpcatalog

import (
	"fmt"
	"strings"
	"testing"
)

const basicPairsJSON = `"basicPairs":[
	{"name":"project-alpha","user":"pk-selector-alpha","key":{"mount":"gatehouse","path":"vendors/langfuse-alpha","field":"pair"}},
	{"name":"project-beta","user":"pk-selector-beta","key":{"mount":"gatehouse-secondary","path":"vendors/langfuse-beta","field":"credentials"}}]`

const basicPairsEntryJSON = `{"name":"langfuse","host":"cloud.langfuse.com","pathPrefixes":["/api/public"],"methods":["GET","POST"],
	"header":"Authorization","basicPair":true,"placeholder":"__vault_LANGFUSE__","pools":["pool-a"],` + basicPairsJSON + `}`

func TestBasicPairsCatalogAcceptsFixedBindings(t *testing.T) {
	for name, entry := range map[string]string{
		"two projects": basicPairsEntryJSON,
		"user header":  strings.Replace(basicPairsEntryJSON, `"basicPair":true`, `"basicPair":true,"pairUserHeader":"X-Langfuse-Public-Key"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			catalog, err := Parse([]byte(`{"entries":[` + entry + `]}`))
			if err != nil {
				t.Fatalf("valid fixed Basic-pair bindings refused: %v", err)
			}
			if e, err := catalog.Match("cloud.langfuse.com", 443, "POST", "/api/public/traces", "pool-a"); err != nil || e.Name != "langfuse" || !e.BasicPair {
				t.Fatalf("binding changed route authorization: entry=%v err=%v", e, err)
			}
		})
	}
}

func TestBasicPairsCatalogUniqueReferencesAndIndexedErrors(t *testing.T) {
	const alphaRef = `{"mount":"gatehouse","path":"vendors/langfuse-alpha","field":"pair"}`
	const betaRef = `{"mount":"gatehouse-secondary","path":"vendors/langfuse-beta","field":"credentials"}`
	for name, tc := range map[string]struct {
		entry string
		index int
	}{
		"distinct references":      {basicPairsEntryJSON, -1},
		"distinct mount":           {strings.Replace(basicPairsEntryJSON, betaRef, `{"mount":"gatehouse-secondary","path":"vendors/langfuse-alpha","field":"pair"}`, 1), -1},
		"distinct path":            {strings.Replace(basicPairsEntryJSON, betaRef, `{"mount":"gatehouse","path":"vendors/langfuse-beta","field":"pair"}`, 1), -1},
		"distinct field":           {strings.Replace(basicPairsEntryJSON, betaRef, `{"mount":"gatehouse","path":"vendors/langfuse-alpha","field":"credentials"}`, 1), -1},
		"invalid first name":       {strings.Replace(basicPairsEntryJSON, `"name":"project-alpha"`, `"name":"invalid binding"`, 1), 0},
		"invalid second name":      {strings.Replace(basicPairsEntryJSON, `"name":"project-beta"`, `"name":"invalid binding"`, 1), 1},
		"duplicate name":           {strings.Replace(basicPairsEntryJSON, `"name":"project-beta"`, `"name":"project-alpha"`, 1), 1},
		"invalid public user":      {strings.Replace(basicPairsEntryJSON, `pk-selector-beta`, `synthetic-public-user:synthetic-secret-do-not-log`, 1), 1},
		"duplicate public user":    {strings.Replace(basicPairsEntryJSON, `pk-selector-beta`, `pk-selector-alpha`, 1), 1},
		"invalid reference":        {strings.Replace(basicPairsEntryJSON, `vendors/langfuse-beta`, `vendors/../langfuse-beta`, 1), 1},
		"duplicate full reference": {strings.Replace(basicPairsEntryJSON, betaRef, alphaRef, 1), 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(`{"entries":[` + tc.entry + `]}`))
			if tc.index < 0 {
				if err != nil {
					t.Fatalf("distinct full references refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid binding accepted")
			}
			for _, value := range []string{"pk-selector-alpha", "pk-selector-beta", "synthetic-public-user", "synthetic-secret-do-not-log"} {
				if strings.Contains(err.Error(), value) {
					t.Fatal("binding validation error echoed a user or credential value")
				}
			}
			if want := fmt.Sprintf("basicPairs[%d]", tc.index); !strings.Contains(err.Error(), want) {
				t.Fatalf("binding validation error lacks %s: %v", want, err)
			}
		})
	}
}

func TestBasicPairsCatalogRejectsAmbiguousOrUnsafeBindings(t *testing.T) {
	for name, entry := range map[string]string{
		"duplicate name":            strings.Replace(basicPairsEntryJSON, `"name":"project-beta"`, `"name":"project-alpha"`, 1),
		"duplicate user":            strings.Replace(basicPairsEntryJSON, `"user":"pk-selector-beta"`, `"user":"pk-selector-alpha"`, 1),
		"missing name":              strings.Replace(basicPairsEntryJSON, `"name":"project-alpha",`, ``, 1),
		"empty name":                strings.Replace(basicPairsEntryJSON, `"name":"project-alpha"`, `"name":""`, 1),
		"missing user":              strings.Replace(basicPairsEntryJSON, `"user":"pk-selector-alpha",`, ``, 1),
		"empty user":                strings.Replace(basicPairsEntryJSON, `"user":"pk-selector-alpha"`, `"user":""`, 1),
		"user contains colon":       strings.Replace(basicPairsEntryJSON, `pk-selector-alpha`, `pk:selector-alpha`, 1),
		"user contains space":       strings.Replace(basicPairsEntryJSON, `pk-selector-alpha`, `pk selector-alpha`, 1),
		"user contains tab":         strings.Replace(basicPairsEntryJSON, `pk-selector-alpha`, `pk\tselector-alpha`, 1),
		"user contains newline":     strings.Replace(basicPairsEntryJSON, `pk-selector-alpha`, `pk\nselector-alpha`, 1),
		"user is placeholder":       strings.Replace(basicPairsEntryJSON, `pk-selector-alpha`, `__vault_LANGFUSE__`, 1),
		"missing key":               strings.Replace(basicPairsEntryJSON, `,"key":{"mount":"gatehouse","path":"vendors/langfuse-alpha","field":"pair"}`, ``, 1),
		"empty key":                 strings.Replace(basicPairsEntryJSON, `{"mount":"gatehouse","path":"vendors/langfuse-alpha","field":"pair"}`, `{}`, 1),
		"missing mount":             strings.Replace(basicPairsEntryJSON, `"mount":"gatehouse",`, ``, 1),
		"mount traversal":           strings.Replace(basicPairsEntryJSON, `"mount":"gatehouse"`, `"mount":"../gatehouse"`, 1),
		"path traversal":            strings.Replace(basicPairsEntryJSON, `vendors/langfuse-alpha`, `vendors/../langfuse-alpha`, 1),
		"path outside vendors":      strings.Replace(basicPairsEntryJSON, `vendors/langfuse-alpha`, `secrets/langfuse-alpha`, 1),
		"empty field":               strings.Replace(basicPairsEntryJSON, `"field":"pair"`, `"field":""`, 1),
		"unknown binding field":     strings.Replace(basicPairsEntryJSON, `"name":"project-alpha"`, `"secret":"not-a-config-field","name":"project-alpha"`, 1),
		"single key and list":       strings.Replace(basicPairsEntryJSON, `"basicPair":true`, `"basicPair":true,"key":{"mount":"gatehouse","path":"vendors/fallback","field":"key"}`, 1),
		"empty list":                strings.Replace(basicPairsEntryJSON, basicPairsJSON, `"basicPairs":[]`, 1),
		"null list":                 strings.Replace(basicPairsEntryJSON, basicPairsJSON, `"basicPairs":null`, 1),
		"not a Basic pair":          strings.Replace(basicPairsEntryJSON, `"basicPair":true`, `"basicPair":false`, 1),
		"Basic user":                strings.Replace(basicPairsEntryJSON, `"basicPair":true`, `"basicUser":true`, 1),
		"Bearer":                    strings.Replace(basicPairsEntryJSON, `"basicPair":true`, `"scheme":"Bearer"`, 1),
		"another credential header": strings.Replace(basicPairsEntryJSON, `"header":"Authorization"`, `"header":"X-Api-Key"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(`{"entries":[` + entry + `]}`)); err == nil {
				t.Fatal("ambiguous or unsafe Basic-pair configuration accepted")
			}
		})
	}
}

func TestBasicPairsCatalogRejectsOtherCredentialKinds(t *testing.T) {
	for name, doc := range map[string]string{
		"postgres":           `{"entries":[{"name":"db","kind":"postgres","host":"db.example.com","pools":["pool-a"],` + basicPairsJSON + `,"postgres":{"database":"core","mount":"database","role":"readonly"}}]}`,
		"browser session":    `{"entries":[` + browserEntryJSON(`,`+basicPairsJSON) + `]}`,
		"gcp":                `{` + gcpPools + `,"entries":[` + strings.Replace(gcsEntry, `"kind":"gcp"`, `"kind":"gcp",`+basicPairsJSON, 1) + `]}`,
		"git":                `{"entries":[` + strings.Replace(gitEntry, `"kind":"git"`, `"kind":"git",`+basicPairsJSON, 1) + `]}`,
		"github api":         `{"entries":[` + strings.Replace(apiEntry, `"kind":"github-api"`, `"kind":"github-api",`+basicPairsJSON, 1) + `]}`,
		"memgraph":           `{"entries":[` + strings.Replace(graphEntry, `"kind":"memgraph"`, `"kind":"memgraph",`+basicPairsJSON, 1) + `]}`,
		"client credentials": clientEntry(clientHeader + `,` + clientBinding + `,` + basicPairsJSON),
		"certificate only":   `{"entries":[{"name":"rpc","host":"rpc.example.com","pathPrefixes":["/v1"],"methods":["GET"],"pools":["pool-a"],` + basicPairsJSON + `,"clientCertificate":{"mount":"gatehouse","path":"vendors/rpc"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("Basic-pair selector accepted for another credential kind")
			}
		})
	}
}
