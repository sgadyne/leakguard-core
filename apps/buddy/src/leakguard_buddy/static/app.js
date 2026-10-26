(() => {
  "use strict";

  let csrf = sessionStorage.getItem("buddy_csrf") || "";
  let currentPage = "sources";
  let selectedRoot = null;
  let currentBrowsePath = "";
  let currentBrowseRoot = null;
  let currentBrowseKind = "local";
  let selectedFinding = null;
  let vaultEntries = [];
  let findingCursor = null;
  const findingCache = new Map();
  let revealed = null;
  let clearClipboardTimer = 0;
  let toastTimer = 0;
  const byId = (id) => document.getElementById(id);
  const node = (tag, cls = "", text = "") => {
    const value = document.createElement(tag);
    if (cls) value.className = cls;
    if (text !== null && text !== undefined) value.textContent = String(text);
    return value;
  };
  const button = (label, action, cls = "small-button", id = "") => {
    const value = node("button", cls, label);
    value.type = "button";
    value.dataset.action = action;
    if (id) value.dataset.id = id;
    return value;
  };
  const clear = (element) => { while (element.firstChild) element.removeChild(element.firstChild); };
  const friendlyErrors = {
    "vault-authentication-failed": "Passphrase was incorrect or encrypted data did not authenticate.",
    "vault-already-created": "Encrypted storage already exists.",
    "vault-not-created": "Create encrypted storage first.",
    "vault-already-unlocked": "This vault is already unlocked.",
    "vault-locked": "Unlock the credential vault first.",
    "vault-passphrase-invalid": "Passphrases must be at least 12 characters.",
    "vault-entry-not-found": "That credential is no longer available.",
    "state-locked": "Unlock encrypted scan storage first.",
    "state-capacity-limit": "Encrypted scan storage reached its current capacity limit.",
    "state-checkpoint-failed": "Encrypted scan progress could not be saved.",
    "state-query-invalid": "The finding page changed. Apply the filters again.",
    "observation-keyring-unavailable": "The native keyring is unavailable or could not verify access.",
    "observation-keyring-not-enabled": "Unattended observation access has not been enabled.",
    "observation-keyring-invalid": "The native keyring rejected this observation key.",
    "session-required": "Your local Buddy session needs to be reopened. Run `leakguard-buddy open` from its private runtime.",
    "session-expired": "Your local Buddy session expired. Run `leakguard-buddy open` from its private runtime.",
    "source-unavailable": "This source is unavailable or offline.",
    "source-not-found": "That source was removed.",
    "source-disabled": "Enable this source before resuming its scan.",
    "scan-progress-stalled": "The scan made no progress within its limits. Select a smaller folder or adjust scan limits before resuming.",
    "scheduler-failed": "The background scheduler stopped unexpectedly. Refresh Buddy or restart the service.",
    "job-not-found": "That scan job is no longer available.",
    "plugin-invalid": "Buddy could not validate this plugin wheel or module.",
    "plugin-review-required": "Confirm that you reviewed and trust this plugin before installing it.",
    "dependency-unavailable": "A plugin dependency is unavailable in this private runtime.",
    "repository-not-found": "Choose an existing Git repository folder.",
    "hook-directory-shared": "Git routes hooks through a shared directory. Buddy will not change hooks outside the selected repository.",
    "hook-operation-failed": "Git hook operation failed. Check that Git is available and the repository is accessible.",
    "request-failed": "The local request failed. No secret or exception details were saved.",
  };

  async function request(path, method = "GET", body = undefined) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (method !== "GET") headers["X-Buddy-CSRF"] = csrf;
    let response;
    try {
      response = await fetch(path, {
        method, headers, credentials: "same-origin", cache: "no-store",
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch (_) {
      throw new Error("The local Buddy service is unavailable.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 && ["session-required", "session-expired"].includes(data.error)) {
        csrf = "";
        sessionStorage.removeItem("buddy_csrf");
      }
      throw new Error(friendlyErrors[data.error] || data.error || friendlyErrors["request-failed"]);
    }
    return data;
  }

  function notify(message, bad = false) {
    const toast = byId("toast");
    toast.textContent = message;
    toast.classList.toggle("error", bad);
    toast.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.add("hidden"), 4200);
  }

  async function bootstrap() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const token = fragment.get("bootstrap");
    if (token) {
      try {
        const response = await fetch("/__bootstrap", {
          method: "POST", credentials: "same-origin", cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token }),
        });
        const data = await response.json();
        if (!response.ok || typeof data.csrf !== "string") throw new Error("bootstrap-rejected");
        csrf = data.csrf;
        sessionStorage.setItem("buddy_csrf", csrf);
        history.replaceState(null, "", location.pathname + location.search);
      } catch (_) {
        history.replaceState(null, "", location.pathname + location.search);
        throw new Error("Buddy could not establish its local session. Start Buddy again from its launcher.");
      }
    }
    if (!csrf) throw new Error("Start Buddy from its launcher to open an authenticated local session.");
  }

  function go(page) {
    currentPage = page;
    document.querySelectorAll(".page").forEach((item) => item.classList.toggle("active", item.id === `page-${page}`));
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
    history.replaceState(null, "", `#${page}`);
    loadPage(page).catch((error) => notify(error.message, true));
  }

  async function loadPage(page) {
    if (page === "sources") await loadSources();
    if (page === "findings") await loadFindings();
    if (page === "vault") await loadVault();
    if (page === "plugins") await loadPlugins();
    if (page === "settings") await loadSettings();
  }

  function badge(text, tone = "") {
    return node("span", `badge ${tone}`.trim(), text || "unknown");
  }

  function categoryLabel(value) {
    return ({
      credentials: "Credentials",
      contact: "Contact information",
      "financial-identifier": "Financial identifier",
      "organization-identifier": "Organization identifier",
      firm: "Firm rule",
      other: "Other",
    })[value] || "Other";
  }

  function stat(label, value, note) {
    const card = node("div", "stat-card");
    card.append(node("span", "stat-label", label), node("strong", "stat-value", value), node("div", "stat-note", note));
    return card;
  }

  async function loadSources() {
    const status = await request("/api/status");
    byId("connection-dot").classList.add("online");
    byId("connection-label").textContent = "Connected to this device";
    const observation = status.observations || {};
    renderObservationGate(observation);
    renderKeyringStatus(observation);
    renderObservationCapacity(observation);
    if (!observation.unlocked) {
      const stats = byId("source-stats"); clear(stats);
      stats.append(stat("Configured sources", "—", "Unlock encrypted scan storage to continue"), stat("Active jobs", "—", ""), stat("Files checked", "—", ""), stat("Successful scans", "—", ""));
      byId("sources-list").replaceChildren(empty("Unlock encrypted scan storage to browse sources."));
      byId("jobs-list").replaceChildren(empty("Unlock encrypted scan storage to view scan activity."));
      return;
    }
    const [sources, jobs] = await Promise.all([request("/api/sources"), request("/api/jobs")]);
    const rows = Array.isArray(sources) ? sources : sources.sources || [];
    const tasks = Array.isArray(jobs) ? jobs : jobs.jobs || [];
    const running = tasks.filter((job) => ["queued", "running", "backoff"].includes(job.state)).length;
    const completed = rows.filter((source) => source.last_success_at).length;
    const totalFiles = tasks.reduce((sum, job) => sum + (Number(job.files_scanned) || 0), 0);
    const stats = byId("source-stats"); clear(stats);
    stats.append(stat("Configured sources", rows.length, "Folders and mounted locations"), stat("Active jobs", running, "Queued, scanning or retrying"), stat("Files checked", totalFiles, "Across visible scan activity"), stat("Successful scans", completed, "Sources with a completed scan"));
    renderSources(rows);
    renderJobs(tasks, rows, status.host || {});
  }

  function renderObservationGate(status) {
    const gate = byId("observation-gate"); clear(gate);
    const opened = status.unlocked === true;
    document.querySelector('[data-action="observation-lock"]').classList.toggle("hidden", !opened);
    gate.classList.toggle("hidden", opened);
    if (opened) return;
    gate.append(node("h2", "", status.created ? "Unlock scan history" : "Set up encrypted scan storage"));
    gate.append(node("p", "", "Buddy keeps scan history and review notes in an encrypted local store. Unlock it to browse locations and run scans. This storage is separate from the credential vault."));
    const actions = node("div", "gate-actions");
    actions.append(button(status.created ? "Unlock scan storage" : "Create encrypted storage", "observation-unlock", "primary"));
    gate.append(actions);
  }

  function renderObservationCapacity(observation) {
    const card = byId("observation-capacity"); clear(card);
    const capacity = Number(observation.capacity_bytes);
    const used = Number(observation.serialized_bytes);
    if (!observation.unlocked || !Number.isFinite(capacity) || capacity <= 0 || !Number.isFinite(used) || used < 0) {
      card.classList.add("hidden");
      return;
    }
    card.classList.remove("hidden");
    const row = node("div", "capacity-line");
    const details = node("div", "capacity-details");
    const percent = Math.min(100, Math.round(used / capacity * 100));
    details.append(node("strong", "", `Encrypted scan storage: ${formatBytes(used)} of ${formatBytes(capacity)} (${percent}%)`));
    details.append(node("span", observation.healthy === false ? "capacity-warning" : "muted", observation.healthy === false ? "Storage health needs attention." : "Current encrypted checkpoint size and alpha capacity limit."));
    const progress = node("progress", "capacity-progress");
    progress.max = capacity;
    progress.value = Math.min(used, capacity);
    progress.setAttribute("aria-label", "Encrypted scan storage usage");
    row.append(details, progress); card.append(row);
  }

  function formatBytes(value) {
    if (value < 1024) return `${Math.round(value)} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
    return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  }

  function renderSources(rows) {
    const list = byId("sources-list"); clear(list);
    if (!rows.length) { list.append(empty("No sources yet. Add a folder or mounted share to begin.")); return; }
    for (const source of rows) {
      const card = node("article", "source-card");
      const content = node("div");
      content.append(node("div", "row-title", source.label || source.root || "Source"), node("div", "path", source.root || ""));
      const meta = node("div", "meta-row");
      meta.append(badge(source.kind || "local"), badge(source.enabled === false ? "paused" : intervalLabel(source.schedule_seconds), source.enabled === false ? "warn" : ""));
      meta.append(badge(source.last_success_at ? `Last success ${dateLabel(source.last_success_at)}` : "Never completed", source.last_success_at ? "good" : "warn"));
      content.append(meta);
      const actions = node("div", "source-actions");
      const scan = button("Scan now", "scan-source", "small-button", source.id);
      scan.disabled = source.enabled === false;
      actions.append(scan);
      actions.append(button(source.enabled === false ? "Enable source" : source.schedule_seconds ? "Pause source" : "Disable source", "toggle-source", "small-button", source.id));
      actions.append(button("Remove", "remove-source", "small-button", source.id));
      card.append(content, actions); list.append(card);
    }
  }

  function renderJobs(jobs, sources, hostStatus = {}) {
    const list = byId("jobs-list"); clear(list);
    if (hostStatus.worker_error) list.append(node("div", "notice", friendlyErrors[hostStatus.worker_error] || "The background scheduler reported an error."));
    if (!jobs.length) { list.append(empty("No scans yet. Your scan progress and coverage will appear here.")); return; }
    const sourceById = new Map(sources.map((source) => [source.id, source]));
    for (const job of jobs.slice(0, 30)) {
      const card = node("article", "job-card");
      const main = node("div");
      const source = sourceById.get(job.source_id);
      main.append(node("div", "job-title", source?.label || source?.root || job.source_id || "Scan job"));
      const details = [job.state, `${job.files_scanned || 0} files checked`];
      if (job.pending_files !== null && job.pending_files !== undefined) details.push(`${job.pending_files} pending`);
      if (job.coverage) details.push(`coverage ${job.coverage}`);
      if (job.stalled_slices) details.push(`${job.stalled_slices} no-progress slices`);
      const policyResets = Number(job.policy_resets) || 0;
      if (policyResets > 0) details.push(`restarted after scan policy changed (${policyResets} ${policyResets === 1 ? "time" : "times"})`);
      if (job.last_error) details.push(friendlyErrors[job.last_error] || `issue ${job.last_error}`);
      main.append(node("div", "path", details.join(" · ")));
      if (["running", "queued"].includes(job.state)) {
        const progress = node("progress", "job-progress"); progress.max = 100; progress.setAttribute("aria-label", "Scan progress");
        const pending = Number(job.pending_files) || 0;
        progress.value = pending ? Math.max(4, Math.min(90, 100 * (Number(job.files_scanned) || 0) / ((Number(job.files_scanned) || 0) + pending))) : 18;
        main.append(progress);
      }
      const actions = node("div", "source-actions");
      if (["running", "queued"].includes(job.state)) actions.append(button("Pause", "job-pause", "small-button", job.id));
      if ((job.state === "paused" || job.state === "backoff") && source?.enabled !== false) actions.append(button("Resume", "job-resume", "small-button", job.id));
      else if (job.state === "paused" && source?.enabled === false) actions.append(badge("Enable source before resuming", "warn"));
      if (["running", "queued", "paused", "backoff"].includes(job.state)) actions.append(button("Cancel", "job-cancel", "small-button", job.id));
      card.append(main, actions); list.append(card);
    }
  }

  function intervalLabel(seconds) {
    if (!seconds) return "manual scans";
    if (seconds >= 604800) return "weekly schedule";
    if (seconds >= 86400) return "daily schedule";
    if (seconds >= 3600) return `every ${Math.round(seconds / 3600)}h`;
    return `every ${Math.max(1, Math.round(seconds / 60))}m`;
  }
  function dateLabel(value) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString(); }
  function empty(message) { return node("div", "empty", message); }

  async function loadFindings(append = false) {
    const status = await request("/api/status");
    const list = byId("findings-list");
    const more = byId("findings-more");
    if (!status.observations?.unlocked) {
      findingCursor = null; findingCache.clear(); clear(list); more.classList.add("hidden");
      const gate = node("div", "card gate");
      gate.append(node("h2", "", "Unlock encrypted scan storage"), node("p", "", "Findings and review notes are kept in encrypted observation storage."), button("Unlock scan storage", "observation-unlock", "primary"));
      list.append(gate); return;
    }
    if (!append) { findingCursor = null; findingCache.clear(); clear(list); }
    const params = new URLSearchParams({ state: byId("finding-state").value });
    const severity = byId("finding-severity").value;
    const category = byId("finding-category").value;
    const annotation = byId("finding-annotation").value;
    const rule = byId("finding-rule").value.trim();
    const source = byId("finding-source").value.trim();
    if (severity) params.set("severity", severity);
    if (category) params.set("category", category);
    if (annotation) params.set("annotation", annotation);
    if (rule) params.set("rule", rule);
    if (source) params.set("source", source);
    if (append && findingCursor) params.set("cursor", findingCursor);
    const result = await request(`/api/findings?${params}`);
    findingCursor = result.next_cursor || null;
    more.classList.toggle("hidden", !findingCursor);
    const canReveal = status.capabilities?.reveal === true;
    const rows = Array.isArray(result) ? result : result.findings || result.rows || [];
    if (append) {
      const priorEmpty = list.querySelector(".empty");
      if (priorEmpty && rows.length) priorEmpty.remove();
    }
    if (!rows.length && !append) list.append(empty(findingCursor ? "No matches on this page. Load more records to continue filtering." : "No findings match these filters."));
    else if (!rows.length && append && !list.childElementCount) list.append(empty("No findings match these filters."));
    for (const finding of rows) {
      findingCache.set(finding.id, finding);
      const card = node("article", "finding-card");
      const main = node("div");
      main.append(node("div", "row-title", finding.rule || "Finding"));
      main.append(node("div", "finding-location", `${finding.source?.path || finding.path || "Unknown path"}:${finding.start_line || finding.line || 1}${finding.end_line && finding.end_line !== finding.start_line ? `–${finding.end_line}` : ""}`));
      const meta = node("div", "finding-meta");
      meta.append(badge(finding.severity || "review", finding.severity === "block" ? "bad" : finding.severity === "review" ? "warn" : ""));
      meta.append(badge(finding.state || "unknown", finding.state === "active" ? "good" : ""));
      meta.append(badge(`Part ${finding.part_id || "text"}`));
      meta.append(badge(`Category ${categoryLabel(finding.category)}`));
      meta.append(badge(`Review ${finding.annotation?.state || "unreviewed"}`, finding.annotation?.state === "reviewed" ? "good" : finding.annotation?.state === "dismissed" ? "warn" : ""));
      if (finding.classification) meta.append(badge(`Evidence ${finding.classification}`));
      meta.append(badge(finding.last_verified ? `Verified ${dateLabel(finding.last_verified)}` : "Not verified"));
      if (finding.coverage) meta.append(badge(`Coverage ${finding.coverage}`));
      main.append(meta);
      const actions = node("div", "finding-actions");
      const path = finding.source?.path || finding.path || "";
      actions.append(button("Copy path", "copy-path", "small-button", path));
      if (canReveal && finding.source_id) {
        const reveal = button("Reveal in folder", "reveal-path", "small-button", finding.source_id);
        reveal.dataset.path = path; actions.append(reveal);
      }
      actions.append(button("Add to vault…", "finding-to-vault", "small-button", finding.id));
      const annotation = finding.annotation?.state || finding.annotation_state || "unreviewed";
      const stateButton = button(annotation === "reviewed" ? "Mark unreviewed" : "Mark reviewed", "annotate-finding", "small-button", finding.id);
      stateButton.dataset.state = annotation === "reviewed" ? "unreviewed" : "reviewed";
      actions.append(stateButton);
      const dismiss = button(annotation === "dismissed" ? "Restore" : "Dismiss", "annotate-finding", "small-button", finding.id);
      dismiss.dataset.state = annotation === "dismissed" ? "unreviewed" : "dismissed";
      actions.append(dismiss);
      card.append(main, actions); list.append(card);
    }
  }

  async function loadVault() {
    const status = await request("/api/vault/status");
    if (!status.unlocked) {
      scrubRevealed();
      const revealDialog = byId("reveal-dialog");
      if (revealDialog.open) revealDialog.close();
    }
    const gate = byId("vault-gate"); clear(gate);
    const list = byId("vault-list"); clear(list);
    if (!status.created) {
      gate.append(node("h2", "", "Create your credential vault"), node("p", "", "Choose a passphrase. The credential vault has its own unlock session; scan jobs never unlock it."), button("Create vault", "credential-unlock", "primary"));
      return;
    }
    if (!status.unlocked) {
      gate.append(node("h2", "", "Vault is locked"), node("p", "", "Unlock the credential vault to add, reveal or manage saved entries."), button("Unlock vault", "credential-unlock", "primary"));
      return;
    }
    gate.append(node("h2", "", "Vault unlocked"), node("p", "", "The credential vault has its own unlock session, separate from scan storage. A saved value appears here only when you explicitly reveal or copy it."), button("Lock vault", "credential-lock", "secondary"));
    const result = await request("/api/vault/entries");
    const entries = result.entries || [];
    vaultEntries = entries;
    if (!entries.length) { list.append(empty("Your vault is empty. Choose Add credential to save one explicitly.")); return; }
    for (const entry of entries) {
      const card = node("article", "vault-card");
      const main = node("div");
      main.append(node("div", "row-title", entry.title || "Credential"));
      if (entry.location) main.append(node("div", "path", entry.location));
      const meta = node("div", "meta-row");
      if (entry.finding_id) meta.append(badge("Linked to finding"));
      if (entry.updated_at) meta.append(badge(`Saved ${dateLabel(entry.updated_at)}`));
      main.append(meta);
      const actions = node("div", "source-actions");
      actions.append(button("Reveal", "reveal-entry", "small-button", entry.id));
      actions.append(button("Copy", "copy-entry", "small-button", entry.id));
      actions.append(button("Edit", "edit-entry", "small-button", entry.id));
      actions.append(button("Delete", "delete-entry", "small-button", entry.id));
      card.append(main, actions); list.append(card);
    }
  }

  async function loadPlugins() {
    const result = await request("/api/plugins");
    const plugins = Array.isArray(result) ? result : result.plugins || [];
    const selectedProfile = byId("plugin-profile").value || "firm";
    const list = byId("plugins-list"); clear(list);
    if (!plugins.length) list.append(empty("No firm plugins are installed. Use a reviewed local wheel to add one."));
    for (const plugin of plugins) {
      const card = node("article", "plugin-card");
      const main = node("div");
      main.append(node("div", "row-title", plugin.name || plugin.id || "Firm plugin"));
      main.append(node("div", "path", `${plugin.id || ""}${plugin.version ? ` · ${plugin.version}` : ""}`));
      const meta = node("div", "meta-row");
      const enabled = Array.isArray(plugin.profiles) ? plugin.profiles.includes(selectedProfile) : plugin.enabled;
      meta.append(badge(plugin.kind || "extension"), badge(`${selectedProfile} profile`), badge(enabled ? "enabled" : "disabled", enabled ? "good" : "warn"));
      if (plugin.api_version || plugin.api) meta.append(badge(`API v${plugin.api_version || plugin.api}`));
      const digest = plugin.sha256 || plugin.wheel_sha256;
      if (digest) meta.append(badge(`sha256 ${digest.slice(0, 12)}`));
      const hasCases = Boolean(plugin.conformance || plugin.has_conformance);
      if (hasCases) meta.append(badge("conformance cases"));
      main.append(meta);
      const actions = node("div", "source-actions");
      actions.append(button(enabled ? "Disable" : "Enable", enabled ? "plugin-disable" : "plugin-enable", "small-button", plugin.id));
      const check = button(hasCases ? "Check conformance" : "No sample cases", "plugin-conformance", "small-button", plugin.id);
      check.disabled = !hasCases; actions.append(check);
      card.append(main, actions); list.append(card);
    }
  }

  async function loadSettings() {
    const data = await request("/api/settings");
    byId("active-profile").value = data.active_profile || data.profile || "credentials";
    byId("worker-policy").textContent = data.worker_policy || "strict";
    byId("scan-workers").value = String(data.scan_workers || 2);
    const summary = byId("settings-summary"); clear(summary);
    summary.append(node("div", "row-title", "Scan policy and storage"));
    const runtime = await request("/api/status");
    const obs = runtime.observations || {};
    const host = runtime.host || {};
    summary.append(node("div", "path", `Current profile: ${data.active_profile || "credentials"} · Shared worker policy: ${data.worker_policy || "strict"} · Scan workers: ${data.scan_workers || 2}`));
    summary.append(node("div", "path", obs.unattended_available ? `Encrypted observation key verified${obs.native_backend ? ` with ${obs.native_backend}` : ""}; unattended access is available.` : `Unattended scans unavailable${obs.keyring_error ? ` (${obs.keyring_error})` : " until a native observation key is explicitly enabled and verified."}`));
    if (host.scheduler) summary.append(node("div", "path", `Scheduler: ${host.scheduler} · Pending jobs: ${host.pending_jobs ?? 0}`));
    if (obs.startup_error) summary.append(node("div", "path", `Automatic resume is unavailable (${obs.startup_error}). Unlock scan storage in Buddy to continue.`));
    const profiles = data.profiles || {};
    const profileNames = Object.keys(profiles);
    if (profileNames.length) summary.append(node("div", "path", `Profiles: ${profileNames.join(", ")}`));
  }

  function renderGitHooks(status) {
    const panel = byId("git-hooks-result"); clear(panel);
    panel.append(node("div", "row-title", status.repository || "Selected repository"));
    const hooks = Array.isArray(status.managed) ? status.managed : [];
    panel.append(node("div", "path", hooks.length ? `Managed hooks: ${hooks.join(", ")}` : "No Buddy-managed hooks are installed here."));
    if (status.profile && hooks.length) panel.append(node("div", "path", `Installed profile: ${status.profile} · worker policy: ${status.worker_policy || "strict"}`));
    if (status.effective_config_path && hooks.length) panel.append(node("div", "path", `Pinned hook config: ${status.effective_config_path}`));
    else if (hooks.length) panel.append(node("div", "path", "These hooks were not installed through Buddy; their effective config and policy are not recorded here."));
    const actions = node("div", "source-actions");
    if (hooks.length) actions.append(button("Uninstall hooks", "git-hooks-uninstall", "small-button"));
    else actions.append(button("Install hooks for this repository", "git-hooks-install", "secondary"));
    panel.append(actions);
  }

  async function loadGitHookStatus(repository) {
    const params = new URLSearchParams({ repository });
    const status = await request(`/api/hooks/status?${params}`);
    byId("git-repository").value = status.repository || repository;
    if (status.profile && ["credentials", "sensitive", "firm"].includes(status.profile)) byId("git-hook-profile").value = status.profile;
    renderGitHooks(status);
  }

  function renderKeyringStatus(observation) {
    const card = byId("keyring-status"); clear(card);
    if (!observation.created) { card.classList.add("hidden"); return; }
    card.classList.remove("hidden");
    const line = node("div", "keyring-line");
    const label = observation.unattended_available
      ? `Native observation key verified${observation.native_backend ? ` · ${observation.native_backend}` : ""}. ${observation.unlocked ? "Background jobs can continue while scan storage is unlocked." : "The next Buddy startup can resume scheduled work; this scan session is currently locked."}`
      : observation.keyring_enabled
        ? `Unattended access was enabled, but the observation key is currently unavailable${observation.keyring_error ? ` (${observation.keyring_error})` : ""}. Unlock scan storage to retry.`
        : "Scheduled scans pause when scan storage locks. Enable native key access to allow Buddy to resume them after restart.";
    line.append(node("p", "", label));
    if (observation.unlocked) {
      const control = button(observation.keyring_enabled ? "Disable unattended access" : "Enable unattended access", "toggle-keyring", "secondary");
      control.dataset.enabled = observation.keyring_enabled ? "false" : "true";
      line.append(control);
    }
    card.append(line);
  }

  async function openBrowser() {
    byId("browser-dialog").showModal();
    selectedRoot = null;
    byId("manual-root-path").value = "";
    byId("source-form").classList.add("hidden");
    clear(byId("directory-browser")); clear(byId("root-choices"));
    byId("browser-status").textContent = "Loading available locations…";
    const response = await request("/api/roots");
    const roots = Array.isArray(response) ? response : response.roots || [];
    const choices = byId("root-choices");
    for (const root of roots) {
      const item = node("button", "root-choice"); item.type = "button"; item.dataset.action = "browse-root"; item.dataset.path = root.path || root.root || ""; item.dataset.kind = root.kind || "local";
      item.append(node("strong", "", root.name || root.label || root.path || "Location"), node("small", "", `${root.status || "available"}${root.path ? ` · ${root.path}` : ""}`));
      item.disabled = root.selectable === false || root.status === "offline" || root.status === "permission-denied";
      choices.append(item);
    }
    if (!roots.length) byId("browser-status").textContent = "No common locations were found. Use a mounted location or add a path below.";
    else byId("browser-status").textContent = "Choose a location. Unavailable and unreadable locations are shown with their status.";
  }

  async function browse(path, root = null, kind = "local", cursor = "", append = false) {
    currentBrowsePath = path; currentBrowseRoot = root; currentBrowseKind = kind;
    const params = new URLSearchParams({ path }); if (root) params.set("root", root); if (cursor) params.set("cursor", cursor);
    const data = await request(`/api/browse?${params}`);
    currentBrowsePath = data.path || currentBrowsePath;
    const pane = byId("directory-browser");
    if (!append) {
      clear(pane);
      byId("browser-status").textContent = `${data.status || "available"} · ${data.path || path}`;
      const heading = node("div", "section-heading");
      heading.append(node("div", "row-title", data.path || path));
      if (data.path && data.path !== root) heading.append(button("Up one level", "browse-parent", "small-button", data.path));
      heading.append(button("Select this folder", "select-current-root", "secondary", data.path || path)); pane.append(heading);
    } else {
      const next = pane.querySelector('[data-action="browse-more"]'); if (next) next.remove();
    }
    const entries = data.entries || [];
    if (!entries.length && !append) pane.append(empty("No visible folders here."));
    for (const entry of entries) {
      const row = node("button", "directory-row"); row.type = "button"; row.dataset.action = "browse-entry"; row.dataset.path = entry.path; row.dataset.root = root || path; row.dataset.kind = kind;
      row.disabled = entry.selectable === false || entry.kind !== "directory";
      row.append(node("span", "", `${entry.kind === "directory" ? "▰" : "▤"}  ${entry.name}`), badge(entry.status || entry.kind || "available", entry.status && entry.status !== "available" ? "warn" : ""));
      pane.append(row);
    }
    if (data.next_cursor) {
      const more = button("Load more", "browse-more", "quiet", data.next_cursor);
      more.dataset.path = currentBrowsePath;
      pane.append(more);
    }
  }

  function chooseRoot(path, kind = "local") {
    selectedRoot = { root: path, kind };
    byId("source-label").value = "";
    byId("source-form").classList.remove("hidden");
    byId("source-form").scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  function openUnlock(target, created = false) {
    byId("unlock-target").value = target;
    const isObservation = target.startsWith("observations");
    const operationCreate = target.includes("create");
    byId("unlock-title").textContent = operationCreate ? "Create encrypted storage" : `Unlock ${isObservation ? "scan storage" : "credential vault"}`;
    byId("unlock-help").textContent = isObservation ? "Scan observations power source browsing, jobs and review notes. Credentials remain locked separately." : "Only this vault session can save, reveal or copy credentials. Scans and plugins use separate interfaces.";
    byId("unlock-passphrase").value = "";
    byId("unlock-dialog").showModal();
    if (created) byId("unlock-passphrase").focus();
  }

  function openCredential(prefill = {}) {
    byId("credential-id").value = prefill.id || "";
    byId("credential-finding-id").value = prefill.finding_id || "";
    byId("credential-title").value = prefill.title || "";
    byId("credential-secret").value = "";
    byId("credential-secret").required = !prefill.id;
    byId("credential-secret").placeholder = prefill.id ? "Leave blank to keep the saved secret" : "Enter secret to save";
    byId("credential-username").value = prefill.username || "";
    byId("credential-location").value = prefill.location || "";
    byId("credential-notes").value = prefill.notes || "";
    byId("credential-clear-username").checked = false;
    byId("credential-clear-notes").checked = false;
    byId("credential-clear-username-row").classList.toggle("hidden", !prefill.id);
    byId("credential-clear-notes-row").classList.toggle("hidden", !prefill.id);
    byId("credential-username").placeholder = prefill.id ? "Leave blank to keep the saved username" : "Optional";
    byId("credential-notes").placeholder = prefill.id ? "Leave blank to keep saved notes" : "Optional";
    const linked = Boolean(prefill.finding_id);
    byId("credential-finding-label").textContent = linked ? `Linked to finding ${prefill.finding_id}` : "Not linked to a finding";
    byId("credential-clear-finding").classList.toggle("hidden", !linked);
    byId("vault-dialog-title").textContent = prefill.id ? "Edit credential" : "Add credential";
    byId("vault-dialog").showModal();
  }

  function scrubRevealed() {
    clear(byId("reveal-content"));
    revealed = null;
  }

  function scrubDialog(dialog) {
    if (dialog.id === "reveal-dialog") scrubRevealed();
    if (dialog.id === "vault-dialog") byId("credential-form").reset();
    if (dialog.id === "unlock-dialog") byId("unlock-passphrase").value = "";
    if (dialog.id === "backup-dialog") { byId("backup-form").reset(); byId("restore-form").reset(); }
  }

  function closeDialog(dialog) {
    scrubDialog(dialog);
    dialog.close();
  }

  async function revealEntry(id, copy = false) {
    const secret = await request(`/api/vault/entries/${encodeURIComponent(id)}/${copy ? "copy" : "reveal"}`, "POST", {});
    if (copy) {
      await copyText(secret.secret || "");
      notify("Secret copied to the clipboard. Buddy will try to clear it in one minute.");
      return;
    }
    revealed = secret;
    const content = byId("reveal-content"); clear(content);
    for (const [label, value] of [["Title", secret.title], ["Username", secret.username], ["Secret", secret.secret], ["Notes", secret.notes]]) {
      if (value === undefined || value === null || value === "") continue;
      content.append(node("label", "", label));
      const shown = node("div", "secret-value", value); content.append(shown);
    }
    byId("reveal-dialog").showModal();
  }

  async function copyText(value) {
    if (!navigator.clipboard?.writeText) throw new Error("Clipboard access is unavailable in this browser.");
    await navigator.clipboard.writeText(value);
    clearTimeout(clearClipboardTimer);
    clearClipboardTimer = setTimeout(async () => {
      try {
        if (navigator.clipboard.readText && await navigator.clipboard.readText() === value) await navigator.clipboard.writeText("");
      } catch (_) { /* Clipboard clearing is best-effort and never overwrites changed content. */ }
    }, 60_000);
  }

  function base64FromBytes(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length)));
    }
    return btoa(binary);
  }

  async function withBusy(element, work) {
    element.disabled = true;
    try { await work(); } catch (error) { notify(error.message, true); }
    finally { element.disabled = false; }
  }

  document.addEventListener("click", (event) => {
    const pageButton = event.target.closest(".nav-link[data-page]");
    if (pageButton) { go(pageButton.dataset.page); return; }
    const actionButton = event.target.closest("[data-action]");
    if (!actionButton) return;
    withBusy(actionButton, async () => {
      const action = actionButton.dataset.action;
      const id = actionButton.dataset.id;
      if (action === "refresh") await loadPage(currentPage);
      else if (action === "open-browser") await openBrowser();
      else if (action === "close-dialog") closeDialog(actionButton.closest("dialog"));
      else if (action === "browse-root") { selectedRoot = { root: actionButton.dataset.path, kind: actionButton.dataset.kind }; await browse(actionButton.dataset.path, actionButton.dataset.path, actionButton.dataset.kind); }
      else if (action === "browse-entry") await browse(actionButton.dataset.path, actionButton.dataset.root, actionButton.dataset.kind);
      else if (action === "browse-parent") {
        const value = actionButton.dataset.id;
        const parts = value.replace(/[\\/]+$/, "").split(/[\\/]/);
        const parent = parts.length > 1 ? parts.slice(0, -1).join(value.includes("\\") ? "\\" : "/") : value;
        await browse(parent, selectedRoot?.root || null, selectedRoot?.kind || "local");
      }
      else if (action === "select-current-root") chooseRoot(actionButton.dataset.id, selectedRoot?.kind || "local");
      else if (action === "use-manual-root") {
        const path = byId("manual-root-path").value.trim();
        if (!path) throw new Error("Enter a root path.");
        chooseRoot(path, path.startsWith("\\\\") ? "unc" : "local");
      }
      else if (action === "browse-more") await browse(currentBrowsePath, currentBrowseRoot, currentBrowseKind, actionButton.dataset.id, true);
      else if (action === "observation-unlock") {
        const status = await request("/api/observations/status"); openUnlock(status.created ? "observations" : "observations-create");
      }
      else if (action === "observation-lock") {
        if (confirm("Lock encrypted scan storage? Any active scan will stop and must resume after you unlock.")) {
          await request("/api/observations/lock", "POST", {}); await loadSources(); notify("Encrypted scan storage locked.");
        }
      }
      else if (action === "credential-unlock") {
        const status = await request("/api/vault/status"); openUnlock(status.created ? "vault" : "vault-create");
      }
      else if (action === "credential-lock") {
        scrubRevealed();
        const revealDialog = byId("reveal-dialog");
        if (revealDialog.open) revealDialog.close();
        await request("/api/vault/lock", "POST", {}); await loadVault(); notify("Credential vault locked.");
      }
      else if (action === "vault-add") { const status = await request("/api/vault/status"); if (!status.unlocked) { openUnlock(status.created ? "vault" : "vault-create"); return; } openCredential(); }
      else if (action === "vault-backup") {
        const status = await request("/api/vault/status");
        if (!status.unlocked) { openUnlock(status.created ? "vault" : "vault-create"); return; }
        byId("backup-passphrase").value = ""; byId("backup-dialog").showModal();
      }
      else if (action === "scan-source") { await request("/api/scans", "POST", { source_id: id }); await loadSources(); notify("Scan queued."); }
      else if (action === "toggle-source") {
        const all = await request("/api/sources"); const sources = Array.isArray(all) ? all : all.sources || []; const source = sources.find((x) => x.id === id);
        await request(`/api/sources/${encodeURIComponent(id)}`, "PATCH", { enabled: source?.enabled === false }); await loadSources();
      }
      else if (action === "remove-source") { if (confirm("Remove this source and its schedule? Scan history is retained.")) { await request(`/api/sources/${encodeURIComponent(id)}`, "DELETE", {}); await loadSources(); } }
      else if (action.startsWith("job-")) { const verb = action.slice(4); await request(`/api/jobs/${encodeURIComponent(id)}/${verb}`, "POST", {}); await loadSources(); }
      else if (action === "filter-findings") await loadFindings(false);
      else if (action === "findings-more") await loadFindings(true);
      else if (action === "toggle-keyring") {
        const enabled = actionButton.dataset.enabled === "true";
        const message = enabled ? "The native OS keyring will hold the encrypted observation key so Buddy can resume scheduled scans after restart. This does not unlock the credential vault. Continue?" : "Disable unattended observation access? Scheduled scans will pause whenever scan storage is locked.";
        if (confirm(message)) { await request("/api/observations/keyring", "POST", { enabled }); await loadSources(); notify(enabled ? "Native observation key verified and enabled." : "Unattended observation access disabled."); }
      }
      else if (action === "copy-path") { await copyText(id); notify("Path copied."); }
      else if (action === "reveal-path") {
        const result = await request(`/api/sources/${encodeURIComponent(id)}/reveal`, "POST", { path: actionButton.dataset.path });
        if (result.status === "copy-path") { await copyText(result.path || actionButton.dataset.path); notify("This system cannot reveal the folder. Path copied instead."); }
        else notify(result.status === "offline" ? "Source is offline." : "Opened the source location.");
      }
      else if (action === "finding-to-vault") {
        const finding = findingCache.get(id) || await request(`/api/findings/${encodeURIComponent(id)}`);
        if (!finding) throw new Error("Finding is no longer available.");
        selectedFinding = finding;
        const vaultStatus = await request("/api/vault/status");
        if (vaultStatus.unlocked) {
          selectedFinding = null;
          openCredential({ title: `${finding.rule || "Finding"} · ${lastComponent(finding.source?.path || finding.path || "source")}`.slice(0, 256), location: finding.source?.path || finding.path || "", finding_id: finding.id });
        } else openUnlock(vaultStatus.created ? "vault-add-finding" : "vault-create-finding");
        byId("unlock-help").textContent = "After unlocking, Buddy fills the title and location only. Enter the credential yourself and choose Save.";
      }
      else if (action === "annotate-finding") { await request(`/api/findings/${encodeURIComponent(id)}/annotation`, "POST", { state: actionButton.dataset.state }); await loadFindings(); }
      else if (action === "reveal-entry") await revealEntry(id);
      else if (action === "copy-entry") await revealEntry(id, true);
      else if (action === "edit-entry") {
        const data = vaultEntries.find((entry) => entry.id === id);
        if (!data) throw new Error("Credential metadata is no longer available.");
        openCredential({ ...data, id });
      }
      else if (action === "delete-entry") { if (confirm("Delete this saved credential? This cannot be undone.")) { await request(`/api/vault/entries/${encodeURIComponent(id)}`, "DELETE", {}); await loadVault(); notify("Credential deleted."); } }
      else if (action === "copy-revealed") { if (!revealed) throw new Error("Reveal a credential first."); await copyText(revealed.secret || ""); notify("Secret copied to the clipboard. Buddy will try to clear it in one minute."); }
      else if (action === "plugin-enable" || action === "plugin-disable") {
        await request(`/api/plugins/${action === "plugin-enable" ? "enable" : "disable"}`, "POST", { id, profile: byId("plugin-profile").value || "firm" }); await loadPlugins();
      }
      else if (action === "plugin-conformance") { const result = await request("/api/plugins/conformance", "POST", { id }); notify(`Conformance: ${result.passed_cases || 0}/${result.total_cases || 0} cases passed${result.passed ? "." : "; review the conformance result."}`); }
      else if (action === "git-hooks-install") {
        const repository = byId("git-repository").value.trim();
        if (!repository) throw new Error("Enter a repository folder first.");
        await request("/api/hooks/install", "POST", { repository, profile: byId("git-hook-profile").value });
        await loadGitHookStatus(repository); notify("Git hooks installed for the selected repository.");
      }
      else if (action === "git-hooks-uninstall") {
        const repository = byId("git-repository").value.trim();
        if (!repository) throw new Error("Enter a repository folder first.");
        if (confirm("Remove Buddy-managed hooks from this selected repository?")) {
          await request("/api/hooks/uninstall", "POST", { repository });
          await loadGitHookStatus(repository); notify("Git hooks removed from the selected repository.");
        }
      }
    }).catch((error) => notify(error.message, true));
  });

  byId("source-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const buttonEl = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(buttonEl, async () => {
      if (!selectedRoot) throw new Error("Select a root first.");
      const exclusions = byId("source-exclusions").value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
      await request("/api/sources", "POST", { root: selectedRoot.root, kind: selectedRoot.kind, label: byId("source-label").value.trim() || null, exclusions, schedule_seconds: Number(byId("source-schedule").value) || null });
      byId("browser-dialog").close(); await loadSources(); notify("Source added.");
    });
  });

  byId("unlock-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const target = byId("unlock-target").value; const passphrase = byId("unlock-passphrase").value; byId("unlock-passphrase").value = "";
      if (target.startsWith("observations")) {
        await request(target.endsWith("create") ? "/api/observations/create" : "/api/observations/unlock", "POST", { passphrase });
        byId("unlock-dialog").close(); await loadSources(); notify("Encrypted scan storage is ready.");
      } else {
        const creating = target.startsWith("vault-create");
        await request(creating ? "/api/vault/create" : "/api/vault/unlock", "POST", { passphrase });
        byId("unlock-dialog").close(); await loadVault();
        if ((target === "vault-add-finding" || target === "vault-create-finding") && selectedFinding) {
          const finding = selectedFinding; selectedFinding = null;
          openCredential({ title: `${finding.rule || "Finding"} · ${lastComponent(finding.source?.path || finding.path || "source")}`.slice(0, 256), location: finding.source?.path || finding.path || "", finding_id: finding.id });
        }
        notify(creating ? "Credential vault created." : "Credential vault unlocked.");
      }
    });
  });

  function lastComponent(path) { return path.split(/[\\/]/).filter(Boolean).slice(-1)[0] || path; }

  byId("credential-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const id = byId("credential-id").value;
      const payload = { title: byId("credential-title").value, location: byId("credential-location").value };
      const username = byId("credential-username").value;
      const notes = byId("credential-notes").value;
      if (!id || username || byId("credential-clear-username").checked) payload.username = byId("credential-clear-username").checked ? "" : username;
      if (!id || notes || byId("credential-clear-notes").checked) payload.notes = byId("credential-clear-notes").checked ? "" : notes;
      if (byId("credential-secret").value) payload.secret = byId("credential-secret").value;
      if (id) payload.finding_id = byId("credential-finding-id").value || null;
      else if (byId("credential-finding-id").value) payload.finding_id = byId("credential-finding-id").value;
      if (!id && !payload.secret) throw new Error("Enter a secret before saving.");
      if (id) await request(`/api/vault/entries/${encodeURIComponent(id)}`, "PATCH", payload);
      else await request("/api/vault/entries", "POST", payload);
      byId("credential-form").reset(); byId("vault-dialog").close(); await loadVault(); notify("Credential saved to the encrypted vault.");
    });
  });

  byId("credential-clear-finding").addEventListener("click", () => {
    byId("credential-finding-id").value = "";
    byId("credential-finding-label").textContent = "Not linked to a finding";
    byId("credential-clear-finding").classList.add("hidden");
  });

  byId("backup-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const passphrase = byId("backup-passphrase").value; byId("backup-passphrase").value = "";
      const result = await request("/api/vault/backup", "POST", { passphrase });
      const raw = atob(result.backup_base64); const bytes = new Uint8Array(raw.length); for (let i=0;i<raw.length;i++) bytes[i] = raw.charCodeAt(i);
      const link = document.createElement("a"); const objectUrl = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" })); link.href = objectUrl; link.download = result.filename || "leakguard-vault.lgbak"; link.click(); setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      notify("Encrypted backup downloaded.");
    });
  });

  byId("restore-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const file = byId("backup-file").files[0]; if (!file) throw new Error("Choose an encrypted backup file.");
      if (file.size > 16 * 1024 * 1024) throw new Error("Vault backup is larger than the 16 MiB alpha limit.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const backup = base64FromBytes(bytes); const backup_passphrase = byId("restore-old-pass").value; const new_passphrase = byId("restore-new-pass").value;
      byId("restore-old-pass").value = ""; byId("restore-new-pass").value = "";
      const status = await request("/api/vault/status");
      const replace = status.created ? confirm("Restore replaces the existing credential vault. The current vault contents will be lost. Continue?") : false;
      if (status.created && !replace) return;
      await request("/api/vault/restore", "POST", { backup, backup_passphrase, new_passphrase, replace });
      byId("restore-form").reset(); byId("backup-dialog").close(); await loadVault(); notify("Encrypted vault restored.");
    });
  });

  byId("plugin-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const file = byId("plugin-wheel").files[0]; if (!file || !file.name.endsWith(".whl")) throw new Error("Choose a local .whl file.");
      if (!byId("plugin-reviewed").checked) throw new Error("Confirm that you reviewed and trust this plugin before installing it.");
      if (file.size > 48_000_000) throw new Error("This alpha accepts wheel files up to 48 MB.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const installed = await request("/api/plugins/install", "POST", { wheel: base64FromBytes(bytes), filename: file.name, reviewed: true });
      byId("plugin-form").reset(); byId("plugin-profile").value = "firm"; await loadPlugins(); notify(installed.id ? `Installed ${installed.id}. Enable it in its separate profile when ready.` : "Plugin installed and inspected.");
    });
  });

  byId("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const result = await request("/api/settings", "POST", { active_profile: byId("active-profile").value, scan_workers: Number(byId("scan-workers").value) });
      await loadSettings(); notify(result.observations_locked ? "Settings saved. Unlock scan storage again to apply them to scanning." : "Settings saved.");
    });
  });

  byId("git-hooks-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = event.currentTarget.querySelector("button[type=submit]");
    await withBusy(submit, async () => {
      const repository = byId("git-repository").value.trim();
      if (!repository) throw new Error("Enter a repository folder first.");
      await loadGitHookStatus(repository);
    });
  });

  byId("plugin-profile").addEventListener("change", () => loadPlugins().catch((error) => notify(error.message, true)));

  document.querySelectorAll("dialog").forEach((dialog) => {
    dialog.addEventListener("cancel", () => scrubDialog(dialog));
    dialog.addEventListener("close", () => scrubDialog(dialog));
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) closeDialog(dialog);
    });
  });

  const initialPage = location.hash.slice(1);
  bootstrap().then(() => {
    go(["sources", "findings", "vault", "plugins", "settings"].includes(initialPage) ? initialPage : "sources");
    setInterval(() => { if (currentPage === "sources") loadSources().catch(() => {}); }, 5000);
  }).catch((error) => {
    byId("connection-label").textContent = error.message;
    byId("connection-dot").classList.add("bad");
    notify(error.message, true);
  });
})();
