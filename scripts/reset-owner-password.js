require("dotenv").config();
const bcrypt = require("bcryptjs");
const { openDatabase, writeAudit } = require("../src/db");
const { databasePath } = require("../src/config");

async function main() {
  const email = (process.env.RESET_OWNER_EMAIL || "owner@example.test").trim().toLowerCase();
  const password = process.env.RESET_OWNER_PASSWORD;
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    throw new Error("Set RESET_OWNER_PASSWORD to a new 12-128 character password in your local environment.");
  }

  const db = openDatabase(databasePath());
  try {
    const owner = db.prepare("SELECT id, is_active FROM users WHERE email = ? COLLATE NOCASE AND role = 'owner'").get(email);
    if (!owner) throw new Error("The requested active Owner account was not found; no password was changed.");
    if (!owner.is_active) throw new Error("This Owner account is disabled; ask an Admin to re-enable it first.");

    const passwordHash = await bcrypt.hash(password, 12);
    const sessions = db.prepare("SELECT sid, session_json FROM sessions").all();
    const ownerSessionIds = [];
    for (const row of sessions) {
      try {
        if (JSON.parse(row.session_json).userId === owner.id) ownerSessionIds.push(row.sid);
      } catch {
        // Leave malformed sessions untouched; they cannot be associated safely with this account.
      }
    }

    const reset = db.transaction(() => {
      db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, owner.id);
      const removeSession = db.prepare("DELETE FROM sessions WHERE sid = ?");
      for (const sid of ownerSessionIds) removeSession.run(sid);
      writeAudit(db, {
        actorId: null,
        action: "account.password.reset",
        resourceType: "user",
        resourceId: owner.id,
        outcome: "success",
        details: { source: "local_cli", invalidatedSessions: ownerSessionIds.length },
      });
    });
    reset();
    console.log(`Password updated for ${email}; ${ownerSessionIds.length} Owner session(s) invalidated. Documents, shares, and other accounts were not changed.`);
  } finally {
    db.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});