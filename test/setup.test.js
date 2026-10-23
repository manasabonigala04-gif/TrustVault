const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const bcrypt = require("bcryptjs");
const { openDatabase } = require("../src/db");

test("initial-admin setup hashes the environment password and refuses a second bootstrap", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "trustvault-admin-"));
  const databasePath = path.join(directory, "bootstrap.sqlite");
  const env = {
    ...process.env,
    DATABASE_PATH: databasePath,
    ADMIN_EMAIL: "first-admin@test.example",
    ADMIN_NAME: "First Admin",
    ADMIN_PASSWORD: "a disposable setup password",
  };
  try {
    const script = path.join(__dirname, "..", "scripts", "setup-admin.js");
    const firstRun = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
    assert.equal(firstRun.status, 0, firstRun.stderr);
    assert.match(firstRun.stdout, /Initial administrator created/);
    const db = openDatabase(databasePath);
    const admin = db.prepare("SELECT email, role, password_hash FROM users").get();
    assert.equal(admin.email, env.ADMIN_EMAIL);
    assert.equal(admin.role, "admin");
    assert.notEqual(admin.password_hash, env.ADMIN_PASSWORD);
    assert.equal(await bcrypt.compare(env.ADMIN_PASSWORD, admin.password_hash), true);
    assert.ok(db.prepare("SELECT 1 FROM audit_events WHERE action = 'admin.bootstrap'").get());
    db.close();
    const secondRun = spawnSync(process.execPath, [script], { env, encoding: "utf8" });
    assert.notEqual(secondRun.status, 0);
    assert.match(secondRun.stderr, /administrator already exists/);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});