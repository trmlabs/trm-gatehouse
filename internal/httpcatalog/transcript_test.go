package httpcatalog

import (
	"strings"
	"testing"
)

func TestTranscriptIsForHeaderEntriesOnly(t *testing.T) {
	llm := strings.NewReplacer(`"host":"slack.com"`, `"host":"llm.example.com"`, `,"requestFields":[{"name":"channel","values":["C0123456789","C0987654321"]}]`, `,"transcript":true`).Replace(slackEntry)
	c, err := Parse([]byte(`{"entries":[` + llm + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Entries()[0].Transcript {
		t.Fatal("transcript not kept")
	}
	if c, err := Parse([]byte(`{"entries":[` + slackEntry + `]}`)); err != nil || c.Entries()[0].Transcript {
		t.Fatalf("transcript is not the default: %v", err)
	}
	git := `{"name":"g","kind":"git","host":"github.com","pools":["pool-a"],"transcript":true,
		"git":{"appID":1,"installationID":2,"repos":[{"repo":"example-org/example-app","access":"read"}]}}`
	if _, err := Parse([]byte(`{"entries":[` + git + `]}`)); err == nil || !strings.Contains(err.Error(), "transcript") {
		t.Fatalf("git transcript entry: %v", err)
	}
}
