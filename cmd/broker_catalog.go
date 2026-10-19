package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/imagerule"
)

var brokerCatalogCmd = &cobra.Command{
	Use:   "broker-catalog",
	Short: "Work with the broker's destination catalog",
}

var brokerCatalogValidateCmd = &cobra.Command{
	Use:   "validate <catalog.yaml|catalog.json>",
	Short: "Validate a destination catalog with the broker's own parser",
	Long: `Validate checks a catalog exactly as the broker will when it loads it:
schema, exact hosts with no wildcards or IP addresses, unique routes, methods,
key locations and pool grants. --allowed-host-suffix holds every host inside
the domains the broker's network policy allows, and --require-pools requires
a pools section that every grant refers to. --image-registry (default
AGENT_VAULT_IMAGE_REGISTRY) is the registry every harness imagePrefix must lie
under. Run it in CI before Terraform
writes the catalog to Vault.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		suffixes, _ := cmd.Flags().GetStringSlice("allowed-host-suffix")
		requirePools, _ := cmd.Flags().GetBool("require-pools")
		if err := catalogSettings(validateSettings(cmd)); err != nil {
			return err
		}
		registry, _ := cmd.Flags().GetString("image-registry")
		if err := imagerule.SetRegistry(registry); err != nil {
			return err
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		return validateBrokerCatalog(data, suffixes, requirePools, cmd.OutOrStdout())
	},
}

func validateBrokerCatalog(data []byte, suffixes []string, requirePools bool, w io.Writer) error {
	document, err := httpcatalog.FromYAML(data)
	if err != nil {
		return err
	}
	catalog, err := httpcatalog.Parse(document)
	if err != nil {
		return err
	}
	if len(suffixes) > 0 {
		if err := catalog.CheckHosts(suffixes); err != nil {
			return err
		}
	}
	if requirePools && len(catalog.Pools()) == 0 {
		return fmt.Errorf("catalog defines no pools")
	}
	kinds := map[string]int{}
	for _, e := range catalog.Entries() {
		kind := e.Kind
		if kind == "" {
			kind = "http"
		}
		kinds[kind]++
	}
	var summary []string
	for _, kind := range []string{"postgres", "http", "git", "github-api"} {
		if kinds[kind] > 0 {
			summary = append(summary, fmt.Sprintf("%s=%d", kind, kinds[kind]))
		}
	}
	_, _ = fmt.Fprintf(w, "valid: pools=%d %s\n", len(catalog.Pools()), strings.Join(summary, " "))
	return nil
}

func init() {
	brokerCatalogValidateCmd.Flags().StringSlice("allowed-host-suffix", nil, "domain every host must be in (repeatable), such as .example.com")
	brokerCatalogValidateCmd.Flags().Bool("require-pools", false, "require a pools section that every grant refers to")
	brokerCatalogValidateCmd.Flags().String("environment", "", "environment every database role must be named for, such as staging")
	brokerCatalogValidateCmd.Flags().String("image-registry", os.Getenv(imagerule.RegistryEnv), "registry host and path every harness imagePrefix must lie under, such as us-docker.pkg.dev/example-project/")
	brokerCatalogCmd.AddCommand(brokerCatalogValidateCmd)
	rootCmd.AddCommand(brokerCatalogCmd)
}
