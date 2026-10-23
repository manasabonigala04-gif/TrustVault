const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const { openDatabase } = require("../src/db");

test("Viewer password reset preserves documents, shares, every session, and other accounts", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "trustvault-viewer-reset-"));
  const filename = path.join(directory, "existing.sqlite");
  const newPassword = "new-viewer-password-safe";
  const db = openDatabase(filename);
  try {
    const ownerId = crypto.randomUUID();
    const viewerId = crypto.randomUUID();
    const adminId = crypto.randomUUID();
    const insertUser = db.prepare("INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)");
    insertUser.run(ownerId, "owner@example.test", "Local Owner", await bcrypt.hash("owner-password", 4), "owner");
    insertUser.run(viewerId, "viewer@example.test", "Local Viewer", await bcrypt.hash("old-viewer-password", 4), "viewer");
    insertUser.run(adminId, "admin@example.test", "Local Admin", await bcrypt.hash("admin-password", 4), "admin");
    const documentId = crypto.randomUUID();
    db.prepare(`INSERT INTO documents (id, owner_id, title, original_filename, storage_key, mime_type, size_bytes)
      VALUES (?, ?, 'Keep this', 'keep.pdf', ?, 'application/pdf', 10)`).run(documentId, ownerId, crypto.randomUUID());
    db.prepare("INSERT INTO permissions (document_id, user_id, permission, granted_by) VALUES (?, ?, 'read', ?)").run(documentId, viewerId, ownerId);
    const viewerSession = crypto.randomUUID();
    const ownerSession = crypto.randomUUID();
    db.prepare("INSERT INTO sessions (sid, session_json, expires_at) VALUES (?, ?, ?)").run(viewerSession, JSON.stringify({ userId: viewerId }), Date.now() + 60000);
    db.prepare("INSERT INTO sessions (sid, session_json, expires_at) VALUES (?, ?, ?)").run(ownerSession, JSON.stringify({ userId: ownerId }), Date.now() + 60000);
    const originalOwnerHash = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(ownerId).password_hash;
    const originalAdminHash = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(adminId).password_hash;
    const script = path.join(__dirname, "..", "scripts", "reset-viewer-password.js");
    const result = spawnSync(process.execPath, [script], {
      env: { ...process.env, DATABASE_PATH: filename, RESET_VIEWER_EMAIL: "viewer@example.test", RESET_VIEWER_PASSWORD: newPassword },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, new RegExp(newPassword));

    const viewer = db.prepare("SELECT id, password_hash FROM users WHERE email = 'viewer@example.test'").get();
    assert.equal(viewer.id, viewerId);
    assert.equal(await bcrypt.compare(newPassword, viewer.password_hash), true);
    assert.equal(await bcrypt.compare("old-viewer-password", viewer.password_hash), false);
    assert.equal(db.prepare("SELECT count(*) AS n FROM documents WHERE id = ? AND owner_id = ?").get(documentId, ownerId).n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM permissions WHERE document_id = ? AND user_id = ?").get(documentId, viewerId).n, 1);
    assert.equal(db.prepare("SELECT password_hash FROM users WHERE id = ?").get(ownerId).password_hash, originalOwnerHash);
    assert.equal(db.prepare("SELECT password_hash FROM users WHERE id = ?").get(adminId).password_hash, originalAdminHash);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sessions").get().n, 2);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sessions WHERE sid = ?").get(viewerSession).n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sessions WHERE sid = ?").get(ownerSession).n, 1);
    assert.ok(db.prepare("SELECT 1 FROM audit_events WHERE action = 'account.password.reset' AND resource_id = ?").get(viewerId));
  } finally {
    db.close();
    await fs.rm(directory, { recursive: true, force: true });
  }
});