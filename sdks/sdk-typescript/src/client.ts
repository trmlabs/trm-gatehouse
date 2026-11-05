import { HttpClient } from "./http.js";
import type { AgentVaultConfig, VaultCreated, VaultDeleted } from "./types.js";
import { VaultClient } from "./vault.js";

/** Options for creating a vault. */
export interface CreateVaultOptions {
  /** Vault name (3-64 chars, lowercase alphanumeric and hyphens only). */
  name: string;
}

/** A newly created vault. */
export interface Vault {
  /** Vault UUID. */
  id: string;
  /** Vault name. */
  name: string;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
}

/** Result of deleting a vault. */
export interface DeleteVaultResult {
  /** Name of the deleted vault. */
  name: string;
  /** Always `true` on success. */
  deleted: boolean;
}

/** Instance-level client for Agent Vault, for an instance-level agent token (`av_agt_...`) that can access multiple vaults. */
export class AgentVault {
  /** @internal */
  readonly _httpClient: HttpClient;

  constructor(config?: AgentVaultConfig) {
    this._httpClient = HttpClient.fromConfig(config);
  }

  /** Returns a {@link VaultClient} scoped to the named vault via the `X-Vault` header. */
  vault(name: string): VaultClient {
    return VaultClient._create(
      this._httpClient.withHeaders({ "X-Vault": name }),
      name,
    );
  }

  /** Create a new vault, throwing ApiError 400 (invalid or reserved name) or 409 (already exists). */
  async createVault(options: CreateVaultOptions): Promise<Vault> {
    const res = await this._httpClient.post<VaultCreated>("/v1/vaults", {
      name: options.name,
    });

    return {
      id: res.id,
      name: res.name,
      createdAt: res.created_at,
    };
  }

  /** Delete a vault by name, throwing ApiError 400 (default vault), 403 (not admin or owner) or 404. */
  async deleteVault(name: string): Promise<DeleteVaultResult> {
    const res = await this._httpClient.del<VaultDeleted>(
      `/v1/vaults/${encodeURIComponent(name)}`,
    );

    return {
      name: res.name,
      deleted: res.deleted,
    };
  }
}
