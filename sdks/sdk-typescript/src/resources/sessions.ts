import type { HttpClient } from "../http.js";
import type { ScopedSession } from "../types.js";

/** Options for creating a vault-scoped session. */
export interface CreateSessionOptions {
  /** Session TTL in seconds (300-604800, i.e. 5 minutes to 7 days).
   *  Defaults to the server's 24h. */
  ttlSeconds?: number;
}

/** Container configuration for routing a sandboxed agent's traffic through the MITM proxy. */
export interface ContainerConfig {
  /** Environment variables to inject into the container. */
  env: {
    /** MITM proxy URL with embedded credentials. */
    HTTPS_PROXY: string;
    /** Same MITM proxy URL — used for plain http:// upstreams via absolute-form forward-proxy requests. */
    HTTP_PROXY: string;
    /** Hosts to bypass the proxy. */
    NO_PROXY: string;
  };
  /** Root CA certificate PEM content; mount it and point CA trust env vars at the path. */
  caCertificate: string;
}

/** A minted vault-scoped session. */
export interface Session {
  /** The vault-scoped session token. */
  token: string;
  /** ISO 8601 expiration timestamp. */
  expiresAt: string;
  /** Agent Vault server base URL. */
  address: string;
  /** Container configuration for transparent MITM proxy routing.
   *  `null` when the server has MITM disabled (`--mitm-port 0`). */
  containerConfig: ContainerConfig | null;
}

/** Default MITM proxy port when the server doesn't advertise one. */
const DEFAULT_MITM_PORT = 14322;

/** Build the proxy environment variables for a container, with CA trust variables pointing at certPath. */
export function buildProxyEnv(
  config: ContainerConfig,
  certPath: string,
): Record<string, string> {
  // Proxy and CA trust variables must stay in sync with augmentEnvWithMITM() in cmd/run.go.
  return {
    HTTPS_PROXY: config.env.HTTPS_PROXY,
    HTTP_PROXY: config.env.HTTP_PROXY,
    NO_PROXY: config.env.NO_PROXY,
    NODE_USE_ENV_PROXY: "1",
    OPENCLAW_PROXY_URL: config.env.HTTPS_PROXY,
    SSL_CERT_FILE: certPath,
    NODE_EXTRA_CA_CERTS: certPath,
    REQUESTS_CA_BUNDLE: certPath,
    CURL_CA_BUNDLE: certPath,
    GIT_SSL_CAINFO: certPath,
    DENO_CERT: certPath,
  };
}

/** Cached MITM metadata (CA cert, host, port) — static for the server's lifetime. */
interface MitmInfo {
  caCertificate: string;
  host: string;
  port: number;
}

/** Resource for minting vault-scoped session tokens (`POST /v1/sessions`). */
export class SessionsResource {
  /** Cached MITM info promise — fetched once, reused across create() calls. */
  private mitmInfoCache: Promise<MitmInfo | null> | null = null;

  constructor(
    private readonly httpClient: HttpClient,
    private readonly vaultName: string,
  ) {}

  /** Mint a vault-scoped session token; `containerConfig` is `null` when the server has MITM disabled. */
  async create(options?: CreateSessionOptions): Promise<Session> {
    const [res, mitmInfo] = await Promise.all([
      this.httpClient.post<ScopedSession>("/v1/sessions", {
        vault: this.vaultName,
        ttl_seconds: options?.ttlSeconds,
      }),
      this.getMitmInfo(),
    ]);

    let containerConfig: ContainerConfig | null = null;
    if (mitmInfo) {
      const proxyUrl = `http://${encodeURIComponent(res.token)}:${encodeURIComponent(this.vaultName)}@${mitmInfo.host}:${mitmInfo.port}`;
      containerConfig = {
        env: {
          HTTPS_PROXY: proxyUrl,
          HTTP_PROXY: proxyUrl,
          NO_PROXY: `localhost,127.0.0.1,${mitmInfo.host}`,
        },
        caCertificate: mitmInfo.caCertificate,
      };
    }

    return {
      token: res.token,
      expiresAt: res.expires_at,
      address: res.av_addr ?? "",
      containerConfig,
    };
  }

  /** Return cached MITM info, fetching once on first call. */
  private getMitmInfo(): Promise<MitmInfo | null> {
    if (!this.mitmInfoCache) {
      this.mitmInfoCache = this.fetchMitmInfo();
    }
    return this.mitmInfoCache;
  }

  /** Fetch the MITM CA certificate and host/port metadata, or null when MITM is disabled. */
  private async fetchMitmInfo(): Promise<MitmInfo | null> {
    const resp = await this.httpClient.raw("GET", "/v1/mitm/ca.pem");
    if (resp.status === 404 || !resp.ok) {
      return null;
    }

    const caCertificate = await resp.text();

    let port = DEFAULT_MITM_PORT;
    const portHeader = resp.headers.get("X-MITM-Port");
    if (portHeader) {
      const parsed = parseInt(portHeader, 10);
      if (parsed > 0 && parsed < 65536) {
        port = parsed;
      }
    }

    const baseUrl = this.httpClient.getBaseUrl();
    let host = "127.0.0.1";
    try {
      const u = new URL(baseUrl);
      if (u.hostname) {
        host = u.hostname;
      }
    } catch {
      // fall back to 127.0.0.1
    }

    return { caCertificate, host, port };
  }
}
