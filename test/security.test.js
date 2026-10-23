const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const { openDatabase } = require("../src/db");
const { createApp, getLoginRateLimitOptions } = require("../src/app");

const PASSWORD = "test-password-long-enough";
const identities = {};
let fixture;

async function send(client, route, options = {}) {
  const headers = new Headers(options.headers || {});
  if (client?.cookie) headers.set("Cookie", client.cookie);
  if (client?.csrf && !["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) headers.set("X-CSRF-Token", client.csrf);
  const response = await fetch(`${fixture.baseUrl}${route}`, { ...options, headers });
  const cookies = response.headers.getSetCookie?.() || [];
  if (client && cookies.length) client.cookie = cookies.at(-1).split(";")[0];
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : null;
  if (client && data?.csrfToken) client.csrf = data.csrfToken;
  return { response, data };
}

async function login(email) {
  const client = { cookie: "", csrf: "" };
  assert.equal((await send(client, "/api/auth/csrf")).response.status, 200);
  const result = await send(client, "/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password: PASSWORD }) });
  assert.equal(result.response.status, 200);
  return client;
}

async function uploadPdf(client, filename = "brief.pdf") {
  const form = new FormData();
  form.append("file", new Blob([Buffer.from("%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF")], { type: "application/pdf" }), filename);
  form.append("title", "Project brief");
  form.append("description", "Private project notes");
  return send(client, "/api/documents", { method: "POST", body: form });
}

test.beforeEach(async () => {
  fixture = { directory: await fs.mkdtemp(path.join(os.tmpdir(), "trustvault-test-")) };
  fixture.storage = path.join(fixture.directory, "private-files");
  fixture.db = openDatabase(path.join(fixture.directory, "test.sqlite"));
  const passwordHash = await bcrypt.hash(PASSWORD, 4);
  const insert = fixture.db.prepare("INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)");
  for (const account of [
    { key: "owner", email: "owner@test.example", role: "owner" },
    { key: "viewer", email: "viewer@test.example", role: "viewer" },
    { key: "admin", email: "admin@test.example", role: "admin" },
    { key: "other", email: "other@test.example", role: "owner" },
  ]) {
    account.id = crypto.randomUUID();
    identities[account.key] = account;
    insert.run(account.id, account.email, account.key, passwordHash, account.role);
  }
  const app = createApp({ db: fixture.db, storageDir: fixture.storage, sessionSecret: "test-secret-".repeat(6), secureCookies: false, rateLimits: false });
  fixture.server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => fixture.server.once("listening", resolve));
  fixture.baseUrl = `http://127.0.0.1:${fixture.server.address().port}`;
});

test.afterEach(async () => {
  if (fixture?.server) await new Promise((resolve) => fixture.server.close(resolve));
  fixture?.db?.close();
  if (fixture?.directory) await fs.rm(fixture.directory, { recursive: true, force: true });
});

test("health works while protected endpoints reject unauthenticated clients", async () => {
  assert.equal((await send(null, "/api/health")).response.status, 200);
  assert.equal((await send(null, "/api/documents")).response.status, 401);
  assert.equal((await send(null, "/api/auth/me")).response.status, 401);
  assert.equal(fixture.db.prepare("SELECT count(*) AS count FROM audit_events WHERE outcome = 'denied'").get().count, 2);
});

test("login regenerates a server session and logout invalidates it", async () => {
  const client = { cookie: "", csrf: "" };
  await send(client, "/api/auth/csrf");
  const anonymousCookie = client.cookie;
  assert.equal((await send(client, "/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.owner.email, password: "wrong-password" }) })).response.status, 401);
  const result = await send(client, "/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.owner.email, password: PASSWORD }) });
  assert.equal(result.response.status, 200);
  assert.notEqual(client.cookie, anonymousCookie);
  assert.match(result.response.headers.get("set-cookie"), /HttpOnly/i);
  assert.match(result.response.headers.get("set-cookie"), /SameSite=Strict/i);
  assert.equal((await send(client, "/api/auth/me")).response.status, 200);
  assert.equal((await send(client, "/api/auth/logout", { method: "POST" })).response.status, 200);
  assert.equal((await send(client, "/api/auth/me")).response.status, 401);
});

test("a viewer cannot read or download a private document by changing its ID", async () => {
  const owner = await login(identities.owner.email);
  const created = await uploadPdf(owner);
  assert.equal(created.response.status, 201);
  const viewer = await login(identities.viewer.email);
  assert.equal((await send(viewer, `/api/documents/${created.data.document.id}`)).response.status, 404);
  assert.equal((await send(viewer, `/api/documents/${created.data.document.id}/download`)).response.status, 404);
  assert.equal(fixture.db.prepare("SELECT count(*) AS count FROM audit_events WHERE actor_id = ? AND outcome = 'denied'").get(identities.viewer.id).count, 2);
});

test("PDF preview is permission-checked, inline, safe, and distinct from download", async () => {
  const owner = await login(identities.owner.email);
  const viewer = await login(identities.viewer.email);
  const created = await uploadPdf(owner);
  const id = created.data.document.id;

  assert.equal((await send(viewer, `/api/documents/${id}/preview`)).response.status, 404);
  assert.equal((await send(owner, `/api/documents/${id}/shares`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.viewer.email, permission: "read" }) })).response.status, 200);

  const preview = await send(viewer, `/api/documents/${id}/preview`);
  assert.equal(preview.response.status, 200);
  assert.match(preview.response.headers.get("content-type"), /^application\/pdf/);
  assert.match(preview.response.headers.get("content-disposition"), /^inline;/);
  assert.equal(preview.response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(preview.response.headers.get("content-security-policy"), "sandbox");
  assert.equal(preview.response.headers.get("cache-control"), "private, no-store, max-age=0");
  assert.equal(preview.response.headers.get("referrer-policy"), "no-referrer");
  assert.doesNotMatch(preview.response.headers.get("content-disposition"), /[A-Za-z]:\\|\//);
  assert.equal(Buffer.from(await preview.response.arrayBuffer()).subarray(0, 5).toString(), "%PDF-");

  const download = await send(viewer, `/api/documents/${id}/download`);
  assert.equal(download.response.status, 200);
  assert.equal(download.response.headers.get("content-type"), "application/octet-stream");
  assert.match(download.response.headers.get("content-disposition"), /^attachment;/);
  assert.equal(Buffer.from(await download.response.arrayBuffer()).subarray(0, 5).toString(), "%PDF-");

  assert.equal((await send(owner, `/api/documents/${id}/shares/${identities.viewer.id}`, { method: "DELETE" })).response.status, 200);
  assert.equal((await send(viewer, `/api/documents/${id}/preview`)).response.status, 404);
  assert.equal((await send(viewer, `/api/documents/${id}/download`)).response.status, 404);
});

test("a share works, and revocation blocks the same document ID immediately", async () => {
  const owner = await login(identities.owner.email);
  const viewer = await login(identities.viewer.email);
  const created = await uploadPdf(owner);
  const id = created.data.document.id;
  assert.equal((await send(owner, `/api/documents/${id}/shares`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.viewer.email, permission: "read" }) })).response.status, 200);
  const permitted = await send(viewer, `/api/documents/${id}/download`);
  assert.equal(permitted.response.status, 200);
  assert.match(permitted.response.headers.get("content-disposition"), /attachment/);
  assert.equal(Buffer.from(await permitted.response.arrayBuffer()).subarray(0, 5).toString(), "%PDF-");
  assert.equal((await send(viewer, `/api/documents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: "Read-only edit" }) })).response.status, 404);
  assert.equal((await send(owner, `/api/documents/${id}/shares`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.viewer.email, permission: "edit" }) })).response.status, 200);
  assert.equal((await send(viewer, `/api/documents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: "Updated by editor" }) })).response.status, 200);
  assert.equal((await send(owner, `/api/documents/${id}/shares/${identities.viewer.id}`, { method: "DELETE" })).response.status, 200);
  assert.equal((await send(viewer, `/api/documents/${id}/download`)).response.status, 404);
});

test("only authorized users can grant access or edit document details", async () => {
  const owner = await login(identities.owner.email);
  const otherOwner = await login(identities.other.email);
  const viewer = await login(identities.viewer.email);
  const created = await uploadPdf(owner);
  const id = created.data.document.id;
  const viewerUpload = new FormData();
  viewerUpload.append("file", new Blob(["%PDF-1.4\n%%EOF"]), "viewer.pdf");
  assert.equal((await send(viewer, "/api/documents", { method: "POST", body: viewerUpload })).response.status, 403);
  assert.equal((await send(viewer, `/api/documents/${id}/shares`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.other.email, permission: "edit" }) })).response.status, 404);
  assert.equal((await send(otherOwner, `/api/documents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: "Stolen" }) })).response.status, 404);
  assert.equal((await send(owner, `/api/documents/${id}/shares`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: identities.viewer.email, permission: "admin" }) })).response.status, 400);
  assert.equal(fixture.db.prepare("SELECT count(*) AS count FROM permissions WHERE document_id = ?").get(id).count, 0);
});

test("upload rejects dangerous extensions, mismatched content, and path traversal", async () => {
  const owner = await login(identities.owner.email);
  const executable = new FormData();
  executable.append("file", new Blob(["not a document"]), "payload.exe");
  assert.equal((await send(owner, "/api/documents", { method: "POST", body: executable })).response.status, 415);
  const wrongContent = new FormData();
  wrongContent.append("file", new Blob(["not pdf"]), "fake.pdf");
  assert.equal((await send(owner, "/api/documents", { method: "POST", body: wrongContent })).response.status, 415);
  const traversal = new FormData();
  traversal.append("file", new Blob(["%PDF-1.4\n%%EOF"]), "../secret.pdf");
  assert.equal((await send(owner, "/api/documents", { method: "POST", body: traversal })).response.status, 400);
  assert.equal(fixture.db.prepare("SELECT count(*) AS count FROM documents").get().count, 0);
});

test("ordinary users cannot access or tamper with audit records", async () => {
  const owner = await login(identities.owner.email);
  const viewer = await login(identities.viewer.email);
  assert.equal((await send(viewer, "/api/admin/audit")).response.status, 403);
  assert.equal((await send(owner, "/api/audit", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "fake", outcome: "success" }) })).response.status, 404);
  assert.equal((await send(owner, "/api/admin/audit", { method: "DELETE" })).response.status, 404);
  const ownActivity = await send(owner, "/api/audit/mine");
  assert.equal(ownActivity.response.status, 200);
  assert.ok(ownActivity.data.events.some((event) => event.action === "auth.login"));
});

test("valid owners can upload, list, edit, download, and delete their documents", async () => {
  const owner = await login(identities.owner.email);
  const created = await uploadPdf(owner);
  const id = created.data.document.id;
  assert.equal(created.response.status, 201);
  assert.equal((await send(owner, "/api/documents")).data.documents.length, 1);
  assert.equal((await send(owner, `/api/documents/${id}/download`)).response.status, 200);
  assert.equal((await send(owner, `/api/documents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: "Updated brief" }) })).response.status, 200);
  assert.equal((await send(owner, `/api/documents/${id}`)).data.document.title, "Updated brief");
  assert.equal((await send(owner, `/api/documents/${id}`, { method: "DELETE" })).response.status, 200);
  assert.equal((await send(owner, `/api/documents/${id}`)).response.status, 404);
});

test("state-changing requests require a session CSRF token", async () => {
  const owner = await login(identities.owner.email);
  const response = await fetch(`${fixture.baseUrl}/api/auth/logout`, { method: "POST", headers: { Cookie: owner.cookie } });
  assert.equal(response.status, 403);
});

test("only admins can change persisted upload settings, and disabled uploads are enforced", async () => {
  const owner = await login(identities.owner.email);
  const admin = await login(identities.admin.email);
  assert.equal((await send(owner, "/api/admin/settings")).response.status, 403);
  const changed = await send(admin, "/api/admin/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ uploadsEnabled: false, maxUploadMb: 4 }) });
  assert.equal(changed.response.status, 200);
  assert.deepEqual(changed.data.settings, { uploadsEnabled: false, maxUploadMb: 4 });
  assert.equal((await send(owner, "/api/documents", { method: "POST", body: new FormData() })).response.status, 503);
  assert.equal((await send(admin, "/api/admin/settings")).data.settings.maxUploadMb, 4);
  assert.ok(fixture.db.prepare("SELECT 1 FROM audit_events WHERE action = 'admin.settings.update'").get());
});

test("admins can manage other users documents and access is logged", async () => {
  const owner = await login(identities.owner.email);
  const admin = await login(identities.admin.email);
  const created = await uploadPdf(owner);
  const id = created.data.document.id;
  assert.equal((await send(admin, "/api/documents")).response.status, 200);
  assert.ok(fixture.db.prepare("SELECT 1 FROM audit_events WHERE actor_id = ? AND action = 'admin.document.list'").get(identities.admin.id));
  assert.equal((await send(admin, `/api/documents/${id}`)).data.document.access_level, "admin");
  assert.equal((await send(admin, `/api/documents/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: "Reviewed brief" }) })).response.status, 200);
  assert.ok(fixture.db.prepare("SELECT 1 FROM audit_events WHERE actor_id = ? AND action = 'admin.document.access'").get(identities.admin.id));
});

test("development login limits are shorter while production retains the stricter policy", async () => {
  assert.deepEqual(getLoginRateLimitOptions("development"), { windowMs: 60_000, limit: 30 });
  assert.deepEqual(getLoginRateLimitOptions("production"), { windowMs: 900_000, limit: 10 });
  const app = createApp({ db: fixture.db, storageDir: fixture.storage, sessionSecret: "test-secret-".repeat(6), secureCookies: false, rateLimits: true, environment: "development" });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const originalBaseUrl = fixture.baseUrl;
  fixture.baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    const client = { cookie: "", csrf: "" };
    await send(client, "/api/auth/csrf");
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const response = await send(client, "/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: "missing@test.example", password: "invalid" }) });
      assert.equal(response.response.status, 401);
    }
    const blocked = await send(client, "/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: "missing@test.example", password: "invalid" }) });
    assert.equal(blocked.response.status, 429);
  } finally {
    fixture.baseUrl = originalBaseUrl;
    await new Promise((resolve) => server.close(resolve));
  }
});