const RAW = process.env.AGENT_ALLOWLIST ?? "";

const ALLOWED = new Set(
  RAW.split(/[\s,]+/)
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean),
);

/** True when AGENT_ALLOWLIST was set with at least one email. */
export function allowlistConfigured(): boolean {
  return ALLOWED.size > 0;
}

/** Whether the email is on the optional Slack allowlist; with none configured, all users pass. */
export function isAllowedEmail(email: string | undefined | null): boolean {
  if (!allowlistConfigured()) return true;
  if (!email) return false;
  return ALLOWED.has(email.trim().toLowerCase());
}
