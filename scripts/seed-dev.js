require("dotenv").config();
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { openDatabase, writeAudit } = require("../src/db");
const { databasePath } = require("../src/config");

async function main() {
  if (process.env.NODE_ENV === "production") throw new Error("Development seed is disabled in production.");
  const db = openDatabase(databasePath());
  try {
    if (db.prepare("SELECT 1 FROM users LIMIT 1").get()) throw new Error("Development seed requires an empty users table.");
    const accounts = [
      { email: "admin@example.test", name: "Local Admin", role: "admin" },
      { email: "owner@example.test", name: "Local Owner", role: "owner" },
      { email: "viewer@example.test", name: "Local Viewer", role: "viewer" },
    ].map((account) => ({ ...account, id: crypto.randomUUID(), password: crypto.randomBytes(18).toString("base64url") }));
    for (const account of accounts) account.passwordHash = await bcrypt.hash(account.password, 10);
    const insert = db.prepare("INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)");
    db.transaction(() => {
      for (const account of accounts) insert.run(account.id, account.email, account.name, account.passwordHash, account.role);
      writeAudit(db, { actorId: accounts[0].id, action: "admin.bootstrap", resourceType: "user", resourceId: accounts[0].id, outcome: "success", details: { source: "development_seed" } });
    })();
    console.log("Disposable local development accounts (shown once):");
    for (const account of accounts) console.log(`${account.role}: ${account.email} / ${account.password}`);
  } finally { db.close(); }
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });