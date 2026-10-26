export type ApiError = Error & { code?: string; status?: number };
let csrf = "";
let onDisconnect: (() => void) | undefined;
let onReconnect: (() => void) | undefined;
const messages: Record<string, string> = {
  "vault-authentication-failed": "Passphrase was incorrect or encrypted data could not authenticate.",
  "vault-passphrase-invalid": "Passphrases must contain at least 12 characters.",
  "vault-locked": "Unlock the credential vault first.", "state-locked": "Unlock scan storage first.",
  "state-capacity-limit": "Encrypted scan storage reached its current capacity limit.",
  "state-checkpoint-failed": "Encrypted scan progress could not be saved.", "source-busy": "The current scan is stopping. Try again after it stops.",
  "source-unavailable": "This source is unavailable or offline.", "outside-root": "Choose a folder inside the selected source.",
  "directory-changed": "The folder changed while loading. Browse it again.", "cursor-invalid": "This listing expired. Reload the first page.",
  "repository-not-found": "Choose an existing Git repository folder.", "hook-directory-shared": "Git uses a shared hooks folder; Buddy will not change hooks outside this repository.",
  "plugin-review-required": "Confirm that you reviewed and trust this plugin before installing it.",
  "extension-runtime-inspection-failed": "Buddy could not inspect the plugin because its private runtime is unavailable.",
  "scan-progress-stalled": "The scan made no progress within its limits. Select a smaller folder or adjust scan limits before resuming."
};
export function setConnectionHandlers(disconnect: () => void, reconnect: () => void) { onDisconnect = disconnect; onReconnect = reconnect; }
async function establishSession(): Promise<void> {
  const tokenParam = new URLSearchParams(location.hash.slice(1)).get("bootstrap");
  let token = tokenParam || "";
  if (!token && window.buddyDesktop) token = (await window.buddyDesktop.bootstrapSession()).token;
  if (token) {
    history.replaceState(null, "", location.pathname + location.search);
    const response = await fetch("/__bootstrap", { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token }) });
    token = "";
    const data = await response.json().catch(() => ({}));
    if (!response.ok || typeof data.csrf !== "string") throw new Error("Buddy could not establish its local session. Restart the desktop app.");
    csrf = data.csrf;
    return;
  }
  const response = await fetch("/api/session", { credentials: "same-origin", cache: "no-store" });
  const data = await response.json().catch(() => ({}));
  if (response.ok && typeof data.csrf === "string") { csrf = data.csrf; return; }
  if (window.buddyDesktop) { await establishSession(); return; }
  throw new Error("Start Password Buddy from its launcher to open an authenticated local session.");
}
export async function initializeSession() { await establishSession(); }
export async function request<T = any>(path: string, method = "GET", body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-Buddy-CSRF"] = csrf;
  let response: Response;
  try { response = await fetch("/api" + path, { method, headers, credentials: "same-origin", cache: "no-store", body: body === undefined ? undefined : JSON.stringify(body), signal }); }
  catch (error) { if ((error as Error).name !== "AbortError") onDisconnect?.(); throw error; }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const code = typeof data.error === "string" ? data.error : "request-failed";
    const error = new Error(messages[code] || (code === "session-required" || code === "session-expired" ? "Your local session expired. Restart Password Buddy." : "The local request failed. Check the details and try again.")) as ApiError;
    error.code = code; error.status = response.status;
    if (response.status >= 500) onDisconnect?.();
    throw error;
  }
  onReconnect?.();
  return data as T;
}