const path = require("node:path");

const projectRoot = path.resolve(__dirname, "..");

function resolveProjectPath(value, fallback) {
  const configured = value || fallback;
  return path.isAbsolute(configured) ? configured : path.resolve(projectRoot, configured);
}

module.exports = {
  databasePath: () => resolveProjectPath(process.env.DATABASE_PATH, "data/trustvault.sqlite"),
  uploadPath: () => resolveProjectPath(process.env.UPLOAD_DIR, "uploads"),
};