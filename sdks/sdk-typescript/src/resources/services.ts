import type { HttpClient } from "../http.js";
import type {
  ServicesList,
  ServicesUpserted,
  ServicesReplaced,
  ServicesCleared,
  ServiceRemoved,
  WireCredentialUsageResult,
} from "../types.js";

/** Bearer token auth — references a credential key. */
export interface BearerAuth {
  type: "bearer";
  /** Credential key for the bearer token (UPPER_SNAKE_CASE). */
  token: string;
}

/** HTTP Basic auth — references credential keys for username and optional password. */
export interface BasicAuth {
  type: "basic";
  /** Credential key for the username (UPPER_SNAKE_CASE). */
  username: string;
  /** Credential key for the password (UPPER_SNAKE_CASE, optional). */
  password?: string;
}

/** API key auth — references a credential key, injected into a header with optional prefix. */
export interface ApiKeyAuth {
  type: "api-key";
  /** Credential key for the API key (UPPER_SNAKE_CASE). */
  key: string;
  /** Header name (defaults to "Authorization"). */
  header?: string;
  /** Prefix prepended to the key value. */
  prefix?: string;
}

/** Custom auth — arbitrary header templates with {{ CREDENTIAL }} placeholders. */
export interface CustomAuth {
  type: "custom";
  /** Map of header name to template value with {{ CREDENTIAL }} placeholders. */
  headers: Record<string, string>;
}

/** Passthrough auth — host is allowlisted, headers flow through, no credential injected. */
export interface PassthroughAuth {
  type: "passthrough";
}

/** Authentication configuration for a service. */
export type ServiceAuth =
  | BearerAuth
  | BasicAuth
  | ApiKeyAuth
  | CustomAuth
  | PassthroughAuth;

/** Surfaces where a substitution may be applied. */
export type SubstitutionSurface = "path" | "query" | "header" | "body" | "websocket";

/** Replaces a placeholder in the request with a credential value before forwarding. */
export interface Substitution {
  /** Credential key (UPPER_SNAKE_CASE) whose value replaces the placeholder. */
  key: string;
  /** Literal placeholder string that appears in the outgoing request. */
  placeholder: string;
  /** Surfaces to scan. Defaults server-side to ["path", "query"] when omitted. */
  in?: SubstitutionSurface[];
}

/** Write shape for a vault service; `name` is a required unique slug, `host` the single matcher (most specific wins). */
export interface ServiceInput {
  /** Service name (slug, 3–64 chars, lowercase alphanumeric and hyphens). Required on write. */
  name?: string;
  /** Host pattern. Accepts `api.stripe.com`, `*.github.com`, or an inline path form like `slack.com/api/*`. */
  host: string;
  /** Whether the service is active. Omitted/undefined is treated as enabled. */
  enabled?: boolean;
  /** Authentication configuration. */
  auth: ServiceAuth;
  /** Optional placeholder→credential substitutions applied before forwarding. */
  substitutions?: Substitution[];
}

/** Read shape for a vault service; composed, not extended, from `ServiceInput` so it cannot be passed to a write method unconverted. */
export interface Service {
  /** Service name (slug). Server populates this on reads. */
  name?: string;
  /** Host pattern. Joined inline form: `api.stripe.com`, `*.github.com`, or `slack.com/api/*`. */
  host: string;
  /** Whether the service is active. Omitted/undefined is treated as enabled. */
  enabled?: boolean;
  /** Authentication configuration. */
  auth: ServiceAuth;
  /** Optional placeholder→credential substitutions applied before forwarding. */
  substitutions?: Substitution[];
}

/** Result of listing services. */
export interface ListServicesResult {
  /** Vault name. */
  vault: string;
  /** All services configured for this vault. */
  services: Service[];
}

/** Result of upserting services. */
export interface SetServicesResult {
  /** Vault name. */
  vault: string;
  /** Service names (slugs) that were upserted. */
  upserted: string[];
  /** Total services count after upsert. */
  servicesCount: number;
}

/** Result of replacing all services. */
export interface ReplaceAllServicesResult {
  /** Vault name. */
  vault: string;
  /** Total services count after replacement. */
  servicesCount: number;
}

/** Result of clearing all services. */
export interface ClearServicesResult {
  /** Vault name. */
  vault: string;
  /** Always true on success. */
  cleared: boolean;
}

/** Result of removing a service. */
export interface RemoveServiceResult {
  /** Vault name. */
  vault: string;
  /** Canonical name (slug) of the service that was removed. */
  removed: string;
  /** Host of the removed service. */
  removedHost?: string;
  /** Total services count after removal. */
  servicesCount: number;
}

/** A service that references a given credential key. */
export interface CredentialUsageEntry {
  /** Service name (slug). Populated by the server even for legacy services. */
  name?: string;
  /** Service host pattern (joined inline form). */
  host: string;
}

/** Result of checking credential usage across services. */
export interface CredentialUsageResult {
  /** Services that reference the given credential key. */
  services: CredentialUsageEntry[];
}

/** Resource for vault services (proxy rules), mapping to `GET/POST/PUT/DELETE /v1/vaults/{name}/services`. */
export class ServicesResource {
  private readonly basePath: string;

  constructor(
    private readonly httpClient: HttpClient,
    vaultName: string,
  ) {
    this.basePath = `/v1/vaults/${encodeURIComponent(vaultName)}/services`;
  }

  /** List all services in this vault. */
  async list(): Promise<ListServicesResult> {
    const res = await this.httpClient.get<ServicesList>(this.basePath);
    return {
      vault: res.vault,
      services: res.services as Service[],
    };
  }

  /** Upsert services by canonical name; resubmitting a name replaces it (vault admin). */
  async set(services: ServiceInput[]): Promise<SetServicesResult> {
    const res = await this.httpClient.post<ServicesUpserted>(this.basePath, {
      services,
    });
    return {
      vault: res.vault,
      upserted: res.upserted,
      servicesCount: res.services_count,
    };
  }

  /** Remove a service by host; the server returns 409 if several share it, so prefer {@link removeByName} for path-scoped ones. */
  async remove(host: string): Promise<RemoveServiceResult> {
    return this.removeByRef(host);
  }

  /** Remove a service by canonical name; unambiguous, never 409 (vault admin). */
  async removeByName(name: string): Promise<RemoveServiceResult> {
    return this.removeByRef(name);
  }

  private async removeByRef(ref: string): Promise<RemoveServiceResult> {
    const res = await this.httpClient.del<ServiceRemoved>(
      `${this.basePath}/${encodeURIComponent(ref)}`,
    );
    return {
      vault: res.vault,
      removed: res.removed,
      removedHost: res.removed_host,
      servicesCount: res.services_count,
    };
  }

  /** Replace ALL services in the vault; destructive, use {@link set} to upsert (vault admin). */
  async replaceAll(services: ServiceInput[]): Promise<ReplaceAllServicesResult> {
    const res = await this.httpClient.put<ServicesReplaced>(this.basePath, {
      services,
    });
    return {
      vault: res.vault,
      servicesCount: res.services_count,
    };
  }

  /** Clear ALL services from the vault (vault admin). */
  async clear(): Promise<ClearServicesResult> {
    const res = await this.httpClient.del<ServicesCleared>(this.basePath);
    return {
      vault: res.vault,
      cleared: res.cleared,
    };
  }

  /** Find which services reference a credential key. */
  async credentialUsage(key: string): Promise<CredentialUsageResult> {
    const res = await this.httpClient.get<WireCredentialUsageResult>(
      `${this.basePath}/credential-usage`,
      { query: { key } },
    );
    return {
      services: res.services,
    };
  }
}
