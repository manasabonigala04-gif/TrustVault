
require("dotenv").config();
const { openDatabase } = require("./src/db");
const { createApp } = require("./src/app");
const { databasePath, uploadPath } = require("./src/config");

const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  console.error("Set SESSION_SECRET to a random value of at least 32 characters.");
  process.exit(1);
}

const db = openDatabase(databasePath());
const app = createApp({ db, storageDir: uploadPath(), sessionSecret, secureCookies: process.env.COOKIE_SECURE !== "false", trustProxy: process.env.TRUST_PROXY === "true" });
const server = app.listen(port, "0.0.0.0", () => console.log(`TrustVault listening on port ${port}`));

function shutdown() {
  server.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
