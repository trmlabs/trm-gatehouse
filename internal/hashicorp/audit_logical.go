package hashicorp

import vaultapi "github.com/hashicorp/vault/api"

// Logical exposes the broker's Vault client to the audit chain for its HMAC key and checkpoint signing.
func (c *Client) Logical() *vaultapi.Logical { return c.api.Logical() }
