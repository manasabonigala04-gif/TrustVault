require("dotenv").config();
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { openDatabase, writeAudit } = require("../src/db");
const { databasePath } = require("../src/config");

async function main() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const displayName = process.env.ADMIN_NAME?.trim();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !displayName || displayName.length > 80 || !password || password.length < 12 || password.length > 128) {
    throw new Error("Set ADMIN_EMAIL, ADMIN_NAME, and an ADMIN_PASSWORD of 12-128 characters in the environment.");
  }
  const db = openDatabase(databasePath());
  try {
    if (db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get()) throw new Error("An administrator already exists; setup can only create the first administrator.");
    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    db.prepare("INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, 'admin')").run(id, email, displayName, passwordHash);
    writeAudit(db, { actorId: id, action: "admin.bootstrap", resourceType: "user", resourceId: id, outcome: "success" });
    console.log(`Initial administrator created for ${email}.`);
  } finally { db.close(); }
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });