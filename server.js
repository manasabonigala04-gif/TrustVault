
require("dotenv").config();

const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { openDatabase, writeAudit } = require("./src/db");
const { createApp } = require("./src/app");
const { databasePath, uploadPath } = require("./src/config");

const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET;

async function start() {
  if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters.");
  }

  const db = openDatabase(databasePath());

  try {
    const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
    const displayName = process.env.ADMIN_NAME?.trim();
    const password = process.env.ADMIN_PASSWORD;

    if (email && displayName && password) {
      const existingAdmin = db
        .prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1")
        .get();

      if (!existingAdmin) {
        if (
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
          displayName.length > 80 ||
          password.length < 12 ||
          password.length > 128
        ) {
          throw new Error("Check ADMIN_EMAIL, ADMIN_NAME and password length (12-128 characters).");
        }

        const id = crypto.randomUUID();
        const passwordHash = await bcrypt.hash(password, 12);

        db.prepare(
          "INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, 'admin')"
        ).run(id, email, displayName, passwordHash);

        writeAudit(db, {
          actorId: id,
          action: "admin.bootstrap",
          resourceType: "user",
          resourceId: id,
          outcome: "success"
        });

        console.log(`Initial administrator created for ${email}.`);
      } else {
        console.log("An administrator already exists; bootstrap skipped.");
      }
    }

    const app = createApp({
      db,
      storageDir: uploadPath(),
      sessionSecret,
      secureCookies: process.env.COOKIE_SECURE !== "false",
      trustProxy: process.env.TRUST_PROXY === "true"
    });

    const server = app.listen(port, "0.0.0.0", () => {
      console.log(`TrustVault listening on port ${port}`);
    });

    function shutdown() {
      server.close(() => {
        db.close();
        process.exit(0);
      });
    }

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } catch (error) {
    db.close();
    throw error;
  }
}

start().catch((error) => {
  console.error("TrustVault startup failed:", error.message);
  process.exit(1);
});

