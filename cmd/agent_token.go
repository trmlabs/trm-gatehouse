package cmd

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Infisical/agent-vault/internal/agenttoken"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

var brokerCatalogMintAgentTokenCmd = &cobra.Command{
	Use:   "mint-agent-token <agent-id>",
	Short: "Mint a per-agent token and print its catalog block",
	Long: `Mint makes a token for one agent: "<agent-id>.<secret>" with 256 random bits
of secret. It prints the token once and never stores it, then the catalog
block to paste into the agent's Automation list, which holds only the token's
SHA-256. Keep the token in the platform's secret store, never in the catalog
or a commit. The agent sends it as the proxy userinfo, with no colon:

  HTTPS_PROXY=http://<token>@host:port

Removing the block revokes the token at the next catalog reload. To rotate,
mint a new token with --keep-hash set to the old token's hash: the block then
lists both, and the old hash is removed once the agent holds the new token.

A token expires: by default 90 days from now, the longest the catalog accepts.
Choose a shorter life with --expires-in. Renew before it passes by minting a
new token with --keep-hash.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		owner, _ := cmd.Flags().GetString("owner")
		entries, _ := cmd.Flags().GetStringSlice("entry")
		write, _ := cmd.Flags().GetStringSlice("write")
		keep, _ := cmd.Flags().GetStringSlice("keep-hash")
		in, _ := cmd.Flags().GetDuration("expires-in")
		spec := agentBlock{ID: args[0], Name: name, Owner: owner, Entries: entries, Write: write, WriteSet: cmd.Flags().Changed("write"), Keep: keep}
		expires, err := tokenExpiry(in, time.Now())
		if err != nil {
			return err
		}
		spec.Expires = expires
		return mintAgentToken(spec, cmd.OutOrStdout())
	},
}

// tokenExpiry is when a token minted at now expires. A token always expires:
// the default is the longest the catalog accepts, and --expires-in chooses a
// shorter life.
func tokenExpiry(in time.Duration, now time.Time) (time.Time, error) {
	if in <= 0 {
		return time.Time{}, errors.New("--expires-in must be positive")
	}
	if in > httpcatalog.MaxTokenLifetime {
		return time.Time{}, fmt.Errorf("--expires-in is longer than the %s a token may live", httpcatalog.MaxTokenLifetime)
	}
	return now.Add(in).UTC().Truncate(time.Second), nil
}

// agentBlock is what mint-agent-token needs to print one Automation block.
type agentBlock struct {
	ID, Name, Owner string
	Entries, Write  []string
	WriteSet        bool
	Keep            []string // earlier hashes the block keeps while a token rotates
	Expires         time.Time
}

func mintAgentToken(spec agentBlock, w io.Writer) error {
	if spec.Name == "" {
		spec.Name = spec.ID
	}
	if spec.Owner == "" || len(spec.Entries) == 0 {
		return errors.New("--owner and at least one --entry are required: the block is the agent's whole authorization")
	}
	token, hash, err := agenttoken.Mint(spec.ID)
	if err != nil {
		return err
	}
	block := renderAgentBlock(spec, append(append([]string(nil), spec.Keep...), hash))
	// The block must be one the broker accepts; refuse to print one it would not.
	if _, err := httpcatalog.ParseAutomationBlock([]byte(block)); err != nil {
		return fmt.Errorf("the catalog block would be refused: %w", err)
	}
	_, err = fmt.Fprintf(w, `Token (shown once, never stored; keep it in the platform's secret store):

%s

Catalog block (holds only the token's hash; paste under "automations:"):

%s`, token, block)
	return err
}

// renderAgentBlock writes one Automation block as YAML. Every string is
// double-quoted, which is valid YAML and keeps an owner address or any odd
// character from changing how the block reads.
func renderAgentBlock(spec agentBlock, hashes []string) string {
	var b strings.Builder
	q := strconv.Quote
	list := func(items []string) string {
		quoted := make([]string, len(items))
		for i, item := range items {
			quoted[i] = q(item)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	fmt.Fprintf(&b, "  - id: %s\n", q(spec.ID))
	fmt.Fprintf(&b, "    name: %s\n", q(spec.Name))
	fmt.Fprintf(&b, "    owner: %s\n", q(spec.Owner))
	fmt.Fprintf(&b, "    entries: %s\n", list(spec.Entries))
	if spec.WriteSet {
		fmt.Fprintf(&b, "    write: %s\n", list(spec.Write))
	}
	fmt.Fprintf(&b, "    tokenSHA256: %s\n", list(hashes))
	fmt.Fprintf(&b, "    expires: %s\n", q(spec.Expires.Format(time.RFC3339)))
	return b.String()
}

func init() {
	f := brokerCatalogMintAgentTokenCmd.Flags()
	f.String("name", "", "short label for audit rows (default: the agent id)")
	f.String("owner", "", "team accountable for the agent: a group's name or object id, or a lower-case contact email")
	f.StringSlice("entry", nil, "catalog entry the agent may use (repeatable); each must also be granted to the pool")
	f.StringSlice("write", nil, "entries where the agent gets the pool's write grant (repeatable); omit to keep the pool's grant on every entry")
	f.StringSlice("keep-hash", nil, "hash of the token being replaced, kept beside the new one while the agent switches (at most one)")
	f.Duration("expires-in", httpcatalog.MaxTokenLifetime, "refuse the token after this long, such as 720h; at most the default, 90 days")
	brokerCatalogCmd.AddCommand(brokerCatalogMintAgentTokenCmd)
}
