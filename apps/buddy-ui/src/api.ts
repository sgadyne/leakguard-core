export type ApiError = Error & { code?: string; status?: number };
let csrf = "";
let bootstrapInFlight: Promise<void> | null = null;
let onDisconnect: (() => void) | undefined;
let onReconnect: (() => void) | undefined;
const messages: Record<string, string> = {
  "vault-authentication-failed": "Passphrase was incorrect or encrypted data could not authenticate.",
  "vault-passphrase-invalid": "Passphrases must contain at least 12 characters.",
  "vault-format-invalid": "The encrypted file is invalid, truncated, or unsupported.",
  "vault-io-failed": "The vault operation could not be written safely. Reopen the vault and check the saved data before retrying.",
  "vault-password-policy-invalid": "Password length must be between 16 and 128 characters.",
  "vault-locked": "Unlock the credential vault first.", "state-locked": "Unlock scan storage first.",
  "state-capacity-limit": "Encrypted scan storage reached its current capacity limit.",
  "state-checkpoint-failed": "Encrypted scan progress could not be saved.", "source-busy": "The current scan is stopping. Try again after it stops.",
  "source-unavailable": "This source is unavailable or offline.", "outside-root": "Choose a folder inside the selected source.",
  "directory-changed": "The folder changed while loading. Browse it again.", "cursor-invalid": "This listing expired. Reload the first page.",
  "state-query-invalid": "This findings page expired. Reload the first page using the current filters.",
  "repository-not-found": "Choose an existing Git repository folder.", "hook-directory-shared": "Git uses a shared hooks folder; Buddy will not change hooks outside this repository.",
  "plugin-review-required": "Confirm that you reviewed and trust this plugin before installing it.",
  "extension-runtime-inspection-failed": "Buddy could not inspect the plugin because its private runtime is unavailable.",
  "scan-progress-stalled": "The scan made no progress within its limits. Select a smaller folder or adjust scan limits before resuming.",
  "scheduler-failed": "The background scheduler stopped unexpectedly. Retry or restart Password Buddy.",
  "worker-still-running": "The scan worker is still stopping. Wait for it to finish before retrying.",
  "request-failed": "The local request failed. No secret or exception details were saved."
};
export function setConnectionHandlers(disconnect: () => void, reconnect: () => void) { onDisconnect = disconnect; onReconnect = reconnect; }
async function establishSession(): Promise<void> {
  if (bootstrapInFlight) return bootstrapInFlight;
  bootstrapInFlight = (async () => {
    const fragmentToken = new URLSearchParams(location.hash.slice(1)).get("bootstrap") || "";
    let token = fragmentToken;
    if (!token && window.buddyDesktop) token = (await window.buddyDesktop.bootstrapSession()).token;
    if (!token) {
      const session = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" });
      const data = await session.json().catch(() => ({}));
      if (session.ok && typeof data.csrf === "string") { csrf = data.csrf; onReconnect?.(); return; }
      throw new Error("Start Password Buddy from its launcher to open an authenticated local session.");
    }
    history.replaceState(null, "", location.pathname + location.search);
    const response = await fetch("/__bootstrap", { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
    token = "";
    const data = await response.json().catch(() => ({}));
    if (!response.ok || typeof data.csrf !== "string") throw new Error("Buddy could not establish its local session. Restart the desktop app.");
    csrf = data.csrf;
    onReconnect?.();
  })().finally(() => { bootstrapInFlight = null; });
  return bootstrapInFlight;
}
export async function initializeSession() { await establishSession(); }
export async function request<T = any>(path: string, method = "GET", body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-Buddy-CSRF"] = csrf;
  const send = () => fetch("/api" + path, { method, headers: { ...headers, ...(method !== "GET" ? { "X-Buddy-CSRF": csrf } : {}) }, credentials: "same-origin", cache: "no-store", body: body === undefined ? undefined : JSON.stringify(body), signal });
  let response: Response;
  try { response = await send(); }
  catch (error) { if ((error as Error).name !== "AbortError") onDisconnect?.(); throw error; }
  if (response.status === 401 && method === "GET") {
    try { await establishSession(); response = await send(); }
    catch (e) { onDisconnect?.(); throw e; }
  } else if (response.status === 401 && window.buddyDesktop) {
    // Establish a fresh session for the next user action; never replay this mutation.
    try { await establishSession(); } catch { /* keep the original safe auth error below */ }
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const rawCode = typeof data.error === "string" ? data.error : "request-failed";
    const code = /^[a-z0-9-]{1,80}$/.test(rawCode) ? rawCode : "request-failed";
    const error = new Error((messages[code] || "The local request failed. Check the details and try again.") + "\nDetails: " + code) as ApiError;
    error.code = code; error.status = response.status;
    if (response.status >= 500) onDisconnect?.();
    throw error;
  }
  onReconnect?.();
  return data as T;
}