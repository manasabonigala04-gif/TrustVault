const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const { openDatabase } = require("../src/db");

test("Owner password reset preserves documents, shares, other users, and other sessions", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "trustvault-reset-"));
  const filename = path.join(directory, "existing.sqlite");
  const oldPassword = "old-owner-password";
  const newPassword = "new-owner-password-safe";
  const db = openDatabase(filename);
  try {
    const ownerId = crypto.randomUUID();
    const viewerId = crypto.randomUUID();
    const adminId = crypto.randomUUID();
    const insertUser = db.prepare("INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)");
    insertUser.run(ownerId, "owner@example.test", "Local Owner", await bcrypt.hash(oldPassword, 4), "owner");
    insertUser.run(viewerId, "viewer@example.test", "Local Viewer", await bcrypt.hash("viewer-password", 4), "viewer");
    insertUser.run(adminId, "admin@example.test", "Local Admin", await bcrypt.hash("admin-password", 4), "admin");
    const documentId = crypto.randomUUID();
    db.prepare(`INSERT INTO documents (id, owner_id, title, original_filename, storage_key, mime_type, size_bytes)
      VALUES (?, ?, 'Keep this', 'keep.pdf', ?, 'application/pdf', 10)`).run(documentId, ownerId, crypto.randomUUID());
    db.prepare("INSERT INTO permissions (document_id, user_id, permission, granted_by) VALUES (?, ?, 'read', ?)").run(documentId, viewerId, ownerId);
    const ownerSession = crypto.randomUUID();
    const adminSession = crypto.randomUUID();
    db.prepare("INSERT INTO sessions (sid, session_json, expires_at) VALUES (?, ?, ?)").run(ownerSession, JSON.stringify({ userId: ownerId }), Date.now() + 60000);
    db.prepare("INSERT INTO sessions (sid, session_json, expires_at) VALUES (?, ?, ?)").run(adminSession, JSON.stringify({ userId: adminId }), Date.now() + 60000);
    const originalAdminHash = db.prepare("SELECT password_hash FROM users WHERE id = ?").get(adminId).password_hash;
    const script = path.join(__dirname, "..", "scripts", "reset-owner-password.js");
    const result = spawnSync(process.execPath, [script], {
      env: { ...process.env, DATABASE_PATH: filename, RESET_OWNER_EMAIL: "owner@example.test", RESET_OWNER_PASSWORD: newPassword },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, new RegExp(newPassword));

    const owner = db.prepare("SELECT id, password_hash FROM users WHERE email = 'owner@example.test'").get();
    assert.equal(owner.id, ownerId);
    assert.equal(await bcrypt.compare(newPassword, owner.password_hash), true);
    assert.equal(await bcrypt.compare(oldPassword, owner.password_hash), false);
    assert.equal(db.prepare("SELECT count(*) AS n FROM documents WHERE id = ? AND owner_id = ?").get(documentId, ownerId).n, 1);
    assert.equal(db.prepare("SELECT count(*) AS n FROM permissions WHERE document_id = ? AND user_id = ?").get(documentId, viewerId).n, 1);
    assert.equal(db.prepare("SELECT password_hash FROM users WHERE id = ?").get(adminId).password_hash, originalAdminHash);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sessions WHERE sid = ?").get(ownerSession).n, 0);
    assert.equal(db.prepare("SELECT count(*) AS n FROM sessions WHERE sid = ?").get(adminSession).n, 1);
    assert.ok(db.prepare("SELECT 1 FROM audit_events WHERE action = 'account.password.reset' AND resource_id = ?").get(ownerId));
  } finally {
    db.close();
    await fs.rm(directory, { recursive: true, force: true });
  }
});