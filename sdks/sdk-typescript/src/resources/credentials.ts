import type { HttpClient } from "../http.js";
import type {
  CredentialsList,
  CredentialsSet,
  CredentialsDeleted,
} from "../types.js";

/** Options for listing credentials; `key` is only accepted with `reveal: true` (enforced by the union type). */
export type ListCredentialsOptions =
  | { reveal?: false; key?: never }
  | { reveal: true; key?: string };

/** A credential entry with its decrypted value. */
export interface Credential {
  /** Credential key (SCREAMING_SNAKE_CASE). */
  key: string;
  /** Decrypted credential value. */
  value: string;
}

/** Result of listing credentials. */
export interface ListCredentialsResult {
  /** All credential key names in the vault. */
  keys: string[];
  /** Decrypted credentials (only present when reveal was requested). */
  credentials?: Credential[];
}

/** Result of setting credentials. */
export interface SetCredentialsResult {
  /** Keys that were set. */
  set: string[];
}

/** Result of deleting credentials. */
export interface DeleteCredentialsResult {
  /** Keys that were deleted. */
  deleted: string[];
}

/** Resource for vault credentials, mapping to `GET/POST/DELETE /v1/credentials`. */
export class CredentialsResource {
  constructor(
    private readonly httpClient: HttpClient,
    private readonly vaultName: string | undefined,
  ) {}

  /** List credential keys; `reveal: true` returns decrypted values (member+ role), `key` narrows to one. */
  async list(options?: ListCredentialsOptions): Promise<ListCredentialsResult> {
    const query: Record<string, string> = {};
    if (this.vaultName) {
      query.vault = this.vaultName;
    }
    if (options?.reveal) {
      query.reveal = "true";
    }
    if (options?.key) {
      query.key = options.key;
    }

    const res = await this.httpClient.get<CredentialsList>("/v1/credentials", {
      query,
    });

    return {
      keys: res.keys,
      credentials: res.credentials?.map((c) => ({
        key: c.key,
        value: c.value ?? "",
      })),
    };
  }

  /** Set credentials; keys must be SCREAMING_SNAKE_CASE and existing keys are overwritten (member+ role). */
  async set(
    credentials: Record<string, string>,
  ): Promise<SetCredentialsResult> {
    const body: Record<string, unknown> = { credentials };
    if (this.vaultName) {
      body.vault = this.vaultName;
    }

    const res = await this.httpClient.post<CredentialsSet>(
      "/v1/credentials",
      body,
    );

    return { set: res.set };
  }

  /** Delete credentials by key; keys must be SCREAMING_SNAKE_CASE (member+ role). */
  async delete(keys: string[]): Promise<DeleteCredentialsResult> {
    const body: Record<string, unknown> = { keys };
    if (this.vaultName) {
      body.vault = this.vaultName;
    }

    const res = await this.httpClient.del<CredentialsDeleted>(
      "/v1/credentials",
      body,
    );

    return { deleted: res.deleted };
  }
}
