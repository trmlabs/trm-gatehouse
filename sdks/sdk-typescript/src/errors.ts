/** Base error class for client-side SDK failures (missing config, network, timeouts). */
export class AgentVaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentVaultError";
  }
}

/** Error returned by the Agent Vault API, carrying status code, error code, and message. */
export class ApiError extends AgentVaultError {
  readonly status: number;
  readonly code: string;
  readonly headers: Headers;

  constructor({
    status,
    code,
    message,
    headers,
  }: {
    status: number;
    code: string;
    message: string;
    headers: Headers;
  }) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.headers = headers;
  }

  static async fromResponse(response: Response): Promise<ApiError> {
    let code = "unknown";
    let message = response.statusText;

    try {
      const body = await response.json();
      if (typeof body === "object" && body !== null) {
        const record = body as Record<string, unknown>;
        const errorField = record.error;
        const messageField = record.message;

        if (typeof errorField === "string") {
          code = errorField;
          message =
            typeof messageField === "string" ? messageField : errorField;
        }
      }
    } catch {
      // Response body wasn't JSON — fall back to statusText
    }

    return new ApiError({
      status: response.status,
      code,
      message,
      headers: response.headers,
    });
  }
}
