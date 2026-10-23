const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const session = require("express-session");

function openDatabase(filename) {
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  const db = new Database(filename);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
      is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      original_filename TEXT NOT NULL,
      storage_key TEXT NOT NULL UNIQUE,
      mime_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      deleted_at TEXT
    );
    CREATE TABLE IF NOT EXISTS permissions (
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
      granted_by TEXT NOT NULL REFERENCES users(id),
      granted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      PRIMARY KEY (document_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id TEXT,
      outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
      details_json TEXT NOT NULL DEFAULT '{}',
      ip_address TEXT
    );
    CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(occurred_at DESC);
    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      session_json TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
    INSERT OR IGNORE INTO settings (key, value) VALUES ('uploads_enabled', 'true'), ('max_upload_mb', '10');
  `);
  return db;
}

class SQLiteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.read = db.prepare("SELECT session_json FROM sessions WHERE sid = ? AND expires_at > ?");
    this.write = db.prepare(`
      INSERT INTO sessions (sid, session_json, expires_at) VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET session_json = excluded.session_json, expires_at = excluded.expires_at
    `);
    this.remove = db.prepare("DELETE FROM sessions WHERE sid = ?");
  }

  get(sid, callback) {
    try {
      const row = this.read.get(sid, Date.now());
      callback(null, row ? JSON.parse(row.session_json) : null);
    } catch (error) {
      callback(error);
    }
  }

  set(sid, value, callback = () => {}) {
    try {
      const expiry = value.cookie?.expires ? Date.parse(value.cookie.expires) : Date.now() + 8 * 60 * 60 * 1000;
      this.write.run(sid, JSON.stringify(value), expiry);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  destroy(sid, callback = () => {}) {
    try {
      this.remove.run(sid);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(sid, value, callback = () => {}) {
    this.set(sid, value, callback);
  }
}

function writeAudit(db, { actorId = null, action, resourceType, resourceId = null, outcome, details = {}, ipAddress = null }) {
  db.prepare(`INSERT INTO audit_events (actor_id, action, resource_type, resource_id, outcome, details_json, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(actorId, action, resourceType, resourceId, outcome, JSON.stringify(details), ipAddress);
}

module.exports = { openDatabase, SQLiteSessionStore, writeAudit };