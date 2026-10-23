const state = { user: null, csrfToken: "", documents: [], filter: "all", search: "", view: "documents", selectedDocumentId: null, toastTimer: null };
const byId = (id) => document.getElementById(id);
const authView = byId("auth-view");
const workspaceView = byId("workspace-view");

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

function showToast(message, isError = false) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.remove("visible"), 3200);
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.csrfToken && !["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) headers.set("X-CSRF-Token", state.csrfToken);
  const response = await fetch(url, { credentials: "same-origin", ...options, headers });
  const type = response.headers.get("content-type") || "";
  const payload = type.includes("application/json") ? await response.json() : null;
  if (response.status === 401 && state.user) await showLogin("Your session ended. Sign in again to continue.");
  if (!response.ok) {
    const error = new Error(payload?.error?.message || "The request could not be completed.");
    error.status = response.status;
    error.code = payload?.error?.code;
    throw error;
  }
  return payload;
}

async function showLogin(message = "") {
  state.user = null;
  authView.hidden = false;
  workspaceView.hidden = true;
  byId("login-message").textContent = message;
  try {
    const response = await fetch("/api/auth/csrf", { credentials: "same-origin" });
    const data = await response.json();
    state.csrfToken = data.csrfToken || "";
  } catch { byId("login-message").textContent = "TrustVault could not connect. Check that the server is running."; }
}

function showWorkspace(user) {
  state.user = user;
  authView.hidden = true;
  workspaceView.hidden = false;
  byId("user-name").textContent = user.displayName;
  byId("user-role").textContent = user.role[0].toUpperCase() + user.role.slice(1);
  byId("user-avatar").textContent = (user.displayName.trim()[0] || "U").toUpperCase();
  document.querySelectorAll(".admin-only").forEach((element) => { element.hidden = user.role !== "admin"; });
  document.querySelectorAll(".upload-trigger, .mobile-upload-trigger").forEach((button) => { button.hidden = !["owner", "admin"].includes(user.role); });
  loadDocuments();
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(date);
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function visibleDocuments() {
  return state.documents.filter((document) => {
    const owned = ["owner", "admin"].includes(document.access_level);
    const matchesFilter = state.filter === "all" || (state.filter === "owned" ? owned : !owned);
    return matchesFilter && `${document.title} ${document.original_filename} ${document.description}`.toLowerCase().includes(state.search.toLowerCase());
  });
}

function renderDocuments() {
  const documents = visibleDocuments();
  byId("documents-loading").hidden = true;
  byId("empty-documents").hidden = documents.length > 0;
  byId("empty-title").textContent = state.search || state.filter !== "all" ? "No matching documents" : "No documents yet";
  byId("empty-copy").textContent = state.search || state.filter !== "all" ? "Try another search or filter." : "Upload a file to make your first secure document space.";
  byId("document-rows").innerHTML = documents.map((document) => {
    const owned = ["owner", "admin"].includes(document.access_level);
    const extension = (document.original_filename || "FILE").split(".").pop().toUpperCase();
    const fileKind = extension.length > 4 ? "FILE" : extension;
    const access = document.access_level === "admin" ? "Admin access" : document.access_level === "edit" ? "Can edit" : owned ? "Owned" : "Shared with you";
    const preview = document.mime_type === "application/pdf"
      ? `<a class="row-action row-action-view" href="/api/documents/${encodeURIComponent(document.id)}/preview" target="_blank" rel="noopener noreferrer" aria-label="View ${escapeHtml(document.title)}" title="View PDF">View</a>`
      : "";
    return `<tr><td><div class="document-cell"><span class="file-icon">${escapeHtml(fileKind)}</span><span class="document-copy"><strong>${escapeHtml(document.title)}</strong><span>${escapeHtml(document.original_filename)} · ${formatSize(document.size_bytes)}</span></span></div></td><td>${escapeHtml(owned ? "You" : document.owner_name)}</td><td><span class="access-tag ${owned ? "" : "shared"}">${escapeHtml(access)}</span></td><td>${formatDate(document.created_at)}</td><td><div class="row-actions">${preview}<button class="row-action" type="button" data-action="download" data-id="${escapeHtml(document.id)}" aria-label="Download ${escapeHtml(document.title)}" title="Download">↓</button><button class="row-action" type="button" data-action="details" data-id="${escapeHtml(document.id)}" aria-label="Details for ${escapeHtml(document.title)}" title="Details">···</button></div></td></tr>`;
  }).join("");
  const owned = state.documents.filter((document) => ["owner", "admin"].includes(document.access_level)).length;
  byId("document-count").textContent = String(state.documents.length);
  byId("stat-owned").textContent = String(owned);
  byId("stat-shared").textContent = String(state.documents.length - owned);
}

async function loadDocuments() {
  byId("documents-loading").hidden = false;
  byId("empty-documents").hidden = true;
  try {
    const { documents } = await api(`/api/documents?q=${encodeURIComponent(state.search)}`);
    state.documents = documents;
    renderDocuments();
  } catch (error) {
    byId("documents-loading").hidden = true;
    byId("empty-documents").hidden = false;
    byId("empty-title").textContent = "Documents could not load";
    byId("empty-copy").textContent = error.message;
    byId("empty-documents").querySelector(".button").hidden = true;
  }
}

function closeSidebar() {
  workspaceView.classList.remove("menu-open");
  byId("menu-button").setAttribute("aria-expanded", "false");
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  for (const [id, visibleView] of [["document-panel", "documents"], ["activity-panel", "activity"], ["people-panel", "people"], ["settings-panel", "settings"]]) byId(id).hidden = view !== visibleView;
  const title = { documents: "Documents", activity: "Activity", people: "People", settings: "Settings" }[view];
  byId("page-title").textContent = title;
  byId("heading-title").textContent = title;
  byId("page-kicker").textContent = { documents: "YOUR WORKSPACE", activity: "WORKSPACE RECORD", people: "WORKSPACE ACCESS", settings: "ADMINISTRATION" }[view];
  byId("heading-description").textContent = { documents: "A calm, secure home for the files that matter.", activity: "A timeline of important document actions.", people: "Create and manage workspace accounts.", settings: "Set the workspace upload policy." }[view];
  byId("heading-actions").hidden = view !== "documents";
  if (view === "activity") loadActivity();
  if (view === "people") loadPeople();
  if (view === "settings") loadSettings();
  closeSidebar();
}

function actionLabel(action) {
  const labels = { "auth.login": "Signed in to TrustVault", "auth.logout": "Signed out of TrustVault", "document.upload": "Uploaded a document", "document.download": "Downloaded a document", "document.edit": "Updated document details", "document.delete": "Deleted a document", "permission.grant": "Shared a document", "permission.revoke": "Revoked document access", "document.access": "A document access request was denied", "admin.document.access": "Administrator accessed a document" };
  return labels[action] || action.replace(/[._]/g, " ");
}

async function loadActivity() {
  const list = byId("activity-list");
  list.textContent = "Loading activity…";
  try {
    const endpoint = state.user.role === "admin" ? "/api/admin/audit?limit=50" : "/api/audit/mine";
    const { events } = await api(endpoint);
    list.innerHTML = events.length ? events.map((event) => `<div class="activity-item"><span class="activity-mark" aria-hidden="true">${event.outcome === "success" ? "✓" : "!"}</span><span class="activity-copy"><strong>${escapeHtml(actionLabel(event.action))}</strong><span>${escapeHtml(event.actor_name || state.user.displayName)} · ${escapeHtml(event.resource_type)}${event.outcome === "denied" ? " · denied" : ""}</span></span><time class="activity-time">${escapeHtml(formatDate(event.occurred_at))}</time></div>`).join("") : '<p class="muted">No activity has been recorded yet.</p>';
    if (events[0]) { byId("stat-activity").textContent = actionLabel(events[0].action); byId("stat-activity-time").textContent = formatDate(events[0].occurred_at); }
  } catch (error) { list.textContent = error.message; }
}

async function loadPeople() {
  const list = byId("people-list");
  list.textContent = "Loading accounts…";
  try {
    const { users } = await api("/api/admin/users");
    list.innerHTML = users.map((user) => `<div class="person-row"><div class="person-copy"><strong>${escapeHtml(user.displayName)}</strong><span>${escapeHtml(user.email)} · ${user.active ? "Active" : "Disabled"}</span></div><span class="role-label">${escapeHtml(user.role)}</span><button class="button button-quiet" type="button" data-action="toggle-user" data-id="${escapeHtml(user.id)}" data-active="${user.active}">${user.active ? "Disable" : "Enable"}</button></div>`).join("");
  } catch (error) { list.textContent = error.message; }
}

async function loadSettings() {
  const message = byId("settings-message");
  message.textContent = "Loading settings…";
  try {
    const { settings } = await api("/api/admin/settings");
    byId("uploads-enabled").checked = settings.uploadsEnabled;
    byId("upload-limit").value = settings.maxUploadMb;
    message.textContent = "";
  } catch (error) { message.textContent = error.message; }
}

async function openDetails(id) {
  try {
    const { document: item } = await api(`/api/documents/${encodeURIComponent(id)}`);
    state.selectedDocumentId = item.id;
    byId("detail-title").textContent = item.title;
    byId("detail-meta").innerHTML = `<span>${escapeHtml(item.original_filename)}</span><span>${escapeHtml(item.mime_type)}</span><span>${formatSize(item.size_bytes)}</span><span>${escapeHtml(formatDate(item.created_at))}</span><span>${escapeHtml(item.access_level === "owner" ? "Owner" : item.access_level === "admin" ? "Admin access" : item.access_level === "edit" ? "Can edit" : "Read only")}</span>`;
    byId("detail-description").textContent = item.description || "No notes added.";
    byId("detail-message").textContent = "";
    byId("view-document").hidden = item.mime_type !== "application/pdf";
    const canManage = ["owner", "admin"].includes(item.access_level);
    byId("share-form").hidden = !canManage;
    byId("share-list-wrap").hidden = !canManage;
    byId("delete-document").hidden = !canManage;
    if (canManage) await loadShares(item.id);
    byId("details-dialog").showModal();
  } catch (error) { showToast(error.message, true); }
}

async function loadShares(id) {
  try {
    const { shares } = await api(`/api/documents/${encodeURIComponent(id)}/shares`);
    byId("share-list").innerHTML = shares.length ? shares.map((share) => `<div class="share-person"><span class="avatar">${escapeHtml((share.display_name || "U")[0].toUpperCase())}</span><span class="share-person-copy"><strong>${escapeHtml(share.display_name)}</strong><span>${escapeHtml(share.email)} · ${escapeHtml(share.permission === "edit" ? "Can edit" : "Can view")}</span></span><button class="button button-quiet" type="button" data-action="revoke" data-id="${escapeHtml(share.user_id)}">Revoke</button></div>`).join("") : '<p class="muted">No one else has access.</p>';
  } catch (error) { byId("share-list").textContent = error.message; }
}

async function downloadDocument(id) {
  try {
    const response = await fetch(`/api/documents/${encodeURIComponent(id)}/download`, { credentials: "same-origin" });
    if (!response.ok) { const data = await response.json().catch(() => null); throw new Error(data?.error?.message || "Download failed."); }
    const objectUrl = URL.createObjectURL(await response.blob());
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = state.documents.find((document) => document.id === id)?.original_filename || "document";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
    showToast("Document downloaded securely.");
  } catch (error) { showToast(error.message, true); }
}

document.querySelectorAll(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll(".upload-trigger, .mobile-upload-trigger").forEach((button) => button.addEventListener("click", () => {
  byId("upload-form").reset(); byId("upload-message").textContent = ""; byId("file-name").textContent = "Choose a file to upload"; byId("upload-dialog").showModal();
}));
document.querySelectorAll(".close-dialog").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
document.querySelectorAll("dialog").forEach((dialog) => dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); }));

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const message = byId("login-message");
  message.textContent = "Signing in…";
  try {
    const result = await api("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) });
    state.csrfToken = result.csrfToken;
    message.textContent = ""; formElement.reset(); showWorkspace(result.user);
  } catch (error) { message.textContent = error.message; }
});

byId("account-button").addEventListener("click", async () => {
  if (!window.confirm("Sign out of TrustVault?")) return;
  try { await api("/api/auth/logout", { method: "POST" }); state.csrfToken = ""; await showLogin("You have signed out."); }
  catch (error) { showToast(error.message, true); }
});

byId("search-input").addEventListener("input", (event) => { state.search = event.currentTarget.value.trim(); renderDocuments(); });
document.querySelectorAll(".segment").forEach((button) => button.addEventListener("click", () => {
  state.filter = button.dataset.filter;
  document.querySelectorAll(".segment").forEach((segment) => segment.classList.toggle("active", segment === button));
  renderDocuments();
}));
byId("document-rows").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (button?.dataset.action === "download") downloadDocument(button.dataset.id);
  if (button?.dataset.action === "details") openDetails(button.dataset.id);
});
byId("upload-file").addEventListener("change", (event) => { byId("file-name").textContent = event.currentTarget.files[0]?.name || "Choose a file to upload"; });
byId("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const submit = formElement.querySelector("button[type=submit]");
  const formData = new FormData(formElement);
  submit.disabled = true; byId("upload-message").textContent = "Checking file and uploading…";
  try {
    await api("/api/documents", { method: "POST", body: formData });
    byId("upload-dialog").close(); formElement.reset(); await loadDocuments(); showToast("Your document is ready.");
  } catch (error) { byId("upload-message").textContent = error.message; }
  finally { submit.disabled = false; }
});

byId("share-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = new FormData(formElement);
  const message = byId("detail-message");
  try {
    await api(`/api/documents/${encodeURIComponent(state.selectedDocumentId)}/shares`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: form.get("email"), permission: form.get("permission") }) });
    formElement.reset(); message.textContent = "Access granted."; message.classList.add("success"); await loadShares(state.selectedDocumentId);
  } catch (error) { message.textContent = error.message; message.classList.remove("success"); }
});
byId("share-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action=revoke]");
  if (!button) return;
  try {
    await api(`/api/documents/${encodeURIComponent(state.selectedDocumentId)}/shares/${encodeURIComponent(button.dataset.id)}`, { method: "DELETE" });
    byId("detail-message").textContent = "Access revoked immediately."; byId("detail-message").classList.add("success"); await loadShares(state.selectedDocumentId); await loadDocuments();
  } catch (error) { byId("detail-message").textContent = error.message; }
});
byId("download-document").addEventListener("click", () => downloadDocument(state.selectedDocumentId));
byId("view-document").addEventListener("click", () => {
  if (state.selectedDocumentId) window.open(`/api/documents/${encodeURIComponent(state.selectedDocumentId)}/preview`, "_blank", "noopener,noreferrer");
});
byId("delete-document").addEventListener("click", async () => {
  if (!window.confirm("Delete this document and revoke everyone’s access? This cannot be undone.")) return;
  try { await api(`/api/documents/${encodeURIComponent(state.selectedDocumentId)}`, { method: "DELETE" }); byId("details-dialog").close(); await loadDocuments(); showToast("Document deleted and access revoked."); }
  catch (error) { byId("detail-message").textContent = error.message; }
});

byId("user-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const message = byId("user-create-message");
  try {
    await api("/api/admin/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(formElement))) });
    formElement.reset(); message.textContent = "Account created."; message.classList.add("success"); await loadPeople();
  } catch (error) { message.textContent = error.message; message.classList.remove("success"); }
});
byId("people-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action=toggle-user]");
  if (!button) return;
  try {
    await api(`/api/admin/users/${encodeURIComponent(button.dataset.id)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ active: button.dataset.active !== "true" }) });
    await loadPeople(); showToast("Account status updated.");
  } catch (error) { showToast(error.message, true); }
});
byId("settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = byId("settings-message");
  try {
    const { settings } = await api("/api/admin/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ uploadsEnabled: byId("uploads-enabled").checked, maxUploadMb: Number(byId("upload-limit").value) }) });
    byId("upload-limit").value = settings.maxUploadMb; message.textContent = "Settings saved."; message.classList.add("success");
  } catch (error) { message.textContent = error.message; message.classList.remove("success"); }
});

byId("menu-button").addEventListener("click", () => {
  const open = !workspaceView.classList.contains("menu-open");
  workspaceView.classList.toggle("menu-open", open); byId("menu-button").setAttribute("aria-expanded", String(open));
});
byId("sidebar-scrim").addEventListener("click", closeSidebar);
document.querySelector(".password-toggle").addEventListener("click", (event) => {
  const input = byId("login-password"); const showing = input.type === "text";
  input.type = showing ? "password" : "text"; event.currentTarget.textContent = showing ? "Show" : "Hide"; event.currentTarget.setAttribute("aria-label", showing ? "Show password" : "Hide password");
});
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) { event.preventDefault(); byId("search-input").focus(); }
});

async function initialize() {
  try {
    const csrfResponse = await fetch("/api/auth/csrf", { credentials: "same-origin" });
    state.csrfToken = (await csrfResponse.json()).csrfToken;
    const current = await api("/api/auth/me"); showWorkspace(current.user);
  } catch { showLogin(); }
}
initialize();