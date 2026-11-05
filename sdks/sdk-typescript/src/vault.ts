import { HttpClient } from "./http.js";
import { CredentialsResource } from "./resources/credentials.js";
import { ServicesResource } from "./resources/services.js";
import { SessionsResource } from "./resources/sessions.js";
import type { VaultClientConfig } from "./types.js";

/** @internal Marker to distinguish the internal construction path. */
const INTERNAL = Symbol("VaultClient.internal");

interface InternalArgs {
  marker: typeof INTERNAL;
  httpClient: HttpClient;
  vaultName: string;
}

/** Vault-scoped client for Agent Vault, built from a vault-scoped session token. */
export class VaultClient {
  /** @internal */
  readonly _httpClient: HttpClient;

  /** Vault name, if known. Undefined for standalone vault-scoped tokens. */
  readonly name: string | undefined;

  /** Sessions resource; only set when the vault name is known. */
  readonly sessions: SessionsResource | undefined;

  /** Services resource; only set when the vault name is known. */
  readonly services: ServicesResource | undefined;

  /** Credentials resource; available on all instances. */
  readonly credentials: CredentialsResource;

  constructor(config?: VaultClientConfig | InternalArgs) {
    if (config && "marker" in config && config.marker === INTERNAL) {
      this._httpClient = config.httpClient;
      this.name = config.vaultName;
      this.sessions = new SessionsResource(config.httpClient, config.vaultName);
      this.services = new ServicesResource(config.httpClient, config.vaultName);
      this.credentials = new CredentialsResource(config.httpClient, config.vaultName);
    } else {
      this._httpClient = HttpClient.fromConfig(config as VaultClientConfig | undefined);
      this.name = undefined;
      this.sessions = undefined;
      this.services = undefined;
      this.credentials = new CredentialsResource(this._httpClient, undefined);
    }
  }

  /** @internal Created by `AgentVault.vault(name)` with a pre-configured HttpClient. */
  static _create(httpClient: HttpClient, vaultName: string): VaultClient {
    return new VaultClient({ marker: INTERNAL, httpClient, vaultName });
  }
}
