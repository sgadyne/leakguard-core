export type ApiError = Error & { code?: string; status?: number };
let csrf = "";
let bootstrapInFlight: Promise<void> | null = null;
let onDisconnect: (() => void) | undefined;
let onReconnect: (() => void) | undefined;
const navigationStatusLabels: Record<string,string> = {
  "permission-denied": "Permission denied",
  offline: "Offline",
  unreadable: "Cannot read this location",
  "not-directory": "This location is not a folder",
  "directory-changed": "Folder changed; browse again",
  "platform-unavailable": "Unavailable on this platform",
};
const messages: Record<string, string> = {
  "ssh-target-invalid": "Enter an SSH alias or host without command options.",
  "remote-path-invalid": "Enter an absolute VM directory without parent traversal.",
  "ssh-timeout": "The VM did not respond within the connection bound. Local protection continues.",
  "ssh-execution-failed": "SSH could not connect with the existing account and host trust. Check the alias using your normal SSH setup.",
  "remote-report-invalid": "The VM response could not be verified. The location remains incomplete.",
  "source-changed": "The location identity changed. Review it before adding it again.",
  "extension-conflict": "Use a unique package name.",
  "extension-startup-artifact": "Review the plugin startup artifact before installing it.",
  "extension-wheel-invalid": "Review the plugin wheel artifact before installing it.",
  "path-invalid": "Enter a valid folder path.",
  "page-invalid": "Choose a valid number of locations to display.",
  "storage-unavailable":"The configured encrypted store is offline or missing. Reconnect it; Buddy will not create an empty replacement.",
  "storage-filesystem-unsupported":"Encrypted storage currently requires a supported local filesystem. Mounted shares can be scanned as additional locations.",
  "storage-ownership-invalid":"Choose a directory owned by your account that other users cannot write.",
  "storage-destination-exists":"The destination already contains data. Choose a new file path.",
  "storage-space-unavailable":"There is insufficient free space to keep a verified rollback copy.",
  "state-storage-unavailable":"Scan storage needs free disk space. Progress remains encrypted; free space and retry.",
  "settings-invalid":"Check the interval, daily time, IANA time zone and absolute exclusions.",
  "vault-authentication-failed": "Passphrase was incorrect or encrypted data could not authenticate.",
  "vault-passphrase-invalid": "Passphrases must contain at least 12 characters.",
  "vault-locked": "Unlock the credential vault first.", "state-locked": "Unlock scan storage first.",
  "state-capacity-limit": "Encrypted scan storage reached its current capacity limit.",
  "state-checkpoint-failed": "Encrypted scan progress could not be saved.", "source-busy": "Wait for the current scan slice to stop before removing this source.",
  "source-unavailable": "This source is unavailable or offline.", "outside-root": "Choose a folder inside the selected source.",
  "directory-changed": "The folder changed while loading. Browse it again.", "cursor-invalid": "This folder listing expired. Browse it again.",
  "state-query-invalid": "This findings page expired. Reload the first page using the current filters.",
  "repository-not-found": "Choose an existing Git repository folder.", "hook-directory-shared": "Git uses a shared hooks folder; Buddy will not change hooks outside this repository.",
  "plugin-review-required": "Confirm that you reviewed and trust this plugin before installing it.",
  "extension-runtime-inspection-failed": "Buddy's private runtime is unavailable.",
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
    const error = new Error((messages[code] || navigationStatusLabels[code] || "The local request failed. Check the details and try again.") + "\nDetails: " + code) as ApiError;
    error.code = code; error.status = response.status;
    if (response.status >= 500) onDisconnect?.();
    throw error;
  }
  onReconnect?.();
  return data as T;
}