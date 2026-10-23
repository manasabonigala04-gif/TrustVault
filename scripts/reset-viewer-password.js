require("dotenv").config();
const bcrypt = require("bcryptjs");
const { openDatabase, writeAudit } = require("../src/db");
const { databasePath } = require("../src/config");

async function main() {
  const email = (process.env.RESET_VIEWER_EMAIL || "viewer@example.test").trim().toLowerCase();
  const password = process.env.RESET_VIEWER_PASSWORD;
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    throw new Error("Set RESET_VIEWER_PASSWORD to a new 12-128 character password in your local environment.");
  }

  const db = openDatabase(databasePath());
  try {
    const viewer = db.prepare("SELECT id, is_active FROM users WHERE email = ? COLLATE NOCASE AND role = 'viewer'").get(email);
    if (!viewer) throw new Error("The requested Viewer account was not found; no password was changed.");
    if (!viewer.is_active) throw new Error("This Viewer account is disabled; ask an Admin to re-enable it first.");

    const passwordHash = await bcrypt.hash(password, 12);
    const reset = db.transaction(() => {
      const result = db.prepare("UPDATE users SET password_hash = ? WHERE id = ? AND role = 'viewer' AND is_active = 1").run(passwordHash, viewer.id);
      if (result.changes !== 1) throw new Error("Viewer account changed during reset; no password was updated.");
      writeAudit(db, {
        actorId: null,
        action: "account.password.reset",
        resourceType: "user",
        resourceId: viewer.id,
        outcome: "success",
        details: { source: "local_cli", role: "viewer", sessionsPreserved: true },
      });
    });
    reset();
    console.log(`Password updated for ${email}. Sessions, documents, shares, and other accounts were preserved.`);
  } finally {
    db.close();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});