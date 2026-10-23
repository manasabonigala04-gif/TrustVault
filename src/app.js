const crypto = require("node:crypto");
const fs = require("node:fs");
const fsPromises = require("node:fs/promises");
const path = require("node:path");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const { SQLiteSessionStore, writeAudit } = require("./db");

const FILE_LIMIT = 10 * 1024 * 1024;
const ALLOWED_TYPES = new Map([[".pdf", "application/pdf"], [".png", "image/png"], [".jpg", "image/jpeg"], [".jpeg", "image/jpeg"], [".txt", "text/plain"]]);
const fileTypeModule = import("file-type");

function getLoginRateLimitOptions(environment) {
  return environment === "development"
    ? { windowMs: 60 * 1000, limit: 30 }
    : { windowMs: 15 * 60 * 1000, limit: 10 };
}

function createApp({ db, storageDir, sessionSecret, secureCookies = process.env.NODE_ENV === "production", trustProxy = false, rateLimits = true, environment = process.env.NODE_ENV }) {
  if (!db) throw new Error("A database connection is required");
  if (!sessionSecret || sessionSecret.length < 32) throw new Error("SESSION_SECRET must contain at least 32 characters");
  const app = express();
  const absoluteStorageDir = path.resolve(storageDir);
  if (trustProxy) app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      },
    },
  }));
  app.use(express.json({ limit: "32kb" }));
  if (rateLimits) app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: "draft-8", legacyHeaders: false }));
  app.use(session({
    name: "trustvault.sid", secret: sessionSecret, store: new SQLiteSessionStore(db), resave: false, saveUninitialized: false, rolling: true,
    cookie: { httpOnly: true, secure: secureCookies, sameSite: "strict", maxAge: 8 * 60 * 60 * 1000, path: "/" },
  }));

  const csrf = (req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    const supplied = Buffer.from(req.get("x-csrf-token") || "");
    const expected = Buffer.from(req.session.csrfToken || "");
    if (!expected.length || supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
      return res.status(403).json({ error: { code: "CSRF_INVALID", message: "Request could not be verified. Refresh and try again." } });
    }
    next();
  };
  app.use("/api", csrf);

  const loginLimiter = rateLimit({ ...getLoginRateLimitOptions(environment), standardHeaders: "draft-8", legacyHeaders: false, skip: () => !rateLimits,
    message: { error: { code: "LOGIN_RATE_LIMITED", message: "Too many sign-in attempts. Try again later." } } });
  const upload = multer({ storage: multer.memoryStorage(), preservePath: true, limits: { fileSize: FILE_LIMIT, files: 1, fields: 5 } });
  const userById = db.prepare("SELECT id, email, display_name, role, is_active, created_at FROM users WHERE id = ?");

  function audit(req, event) {
    writeAudit(db, { ...event, ipAddress: req.ip || null });
  }

  function publicUser(user) {
    return { id: user.id, email: user.email, displayName: user.display_name, role: user.role, createdAt: user.created_at };
  }

  function requireAuth(req, res, next) {
    if (!req.session.userId) {
      audit(req, { action: "auth.required", resourceType: "endpoint", outcome: "denied", details: { method: req.method, path: req.path.slice(0, 100) } });
      return res.status(401).json({ error: { code: "AUTH_REQUIRED", message: "Sign in to continue." } });
    }
    const user = userById.get(req.session.userId);
    if (!user || !user.is_active) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: { code: "AUTH_REQUIRED", message: "Sign in to continue." } });
    }
    req.user = user;
    next();
  }

  function requireAdmin(req, res, next) {
    if (req.user.role !== "admin") {
      audit(req, { actorId: req.user.id, action: "admin.access", resourceType: "endpoint", outcome: "denied", details: { path: req.path.slice(0, 100) } });
      return res.status(403).json({ error: { code: "FORBIDDEN", message: "Administrator access is required." } });
    }
    next();
  }

  function validId(value) {
    return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
  }

  function getDocumentAccess(documentId, user) {
    return db.prepare(`
      SELECT d.*, CASE WHEN d.owner_id = ? THEN 'owner' WHEN ? = 'admin' THEN 'admin' ELSE p.permission END AS access_level
      FROM documents d LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
      WHERE d.id = ? AND d.deleted_at IS NULL AND (d.owner_id = ? OR p.user_id = ? OR ? = 'admin')
    `).get(user.id, user.role, user.id, documentId, user.id, user.id, user.role);
  }

  function accessDenied(req, documentId) {
    audit(req, { actorId: req.user.id, action: "document.access", resourceType: "document", resourceId: typeof documentId === "string" ? documentId.slice(0, 100) : null, outcome: "denied" });
    return { error: { code: "NOT_FOUND", message: "Document was not found." } };
  }

  function auditAdminDocumentAccess(req, document, operation) {
    if (req.user.role === "admin" && document.owner_id !== req.user.id) {
      audit(req, { actorId: req.user.id, action: "admin.document.access", resourceType: "document", resourceId: document.id, outcome: "success", details: { operation } });
    }
  }

  function requireUploadRole(req, res, next) {
    if (!["owner", "admin"].includes(req.user.role)) {
      audit(req, { actorId: req.user.id, action: "document.upload", resourceType: "document", outcome: "denied" });
      return res.status(403).json({ error: { code: "FORBIDDEN", message: "Only document owners can upload files." } });
    }
    if (db.prepare("SELECT value FROM settings WHERE key = 'uploads_enabled'").get()?.value !== "true") {
      return res.status(503).json({ error: { code: "UPLOADS_DISABLED", message: "Uploads are temporarily disabled by an administrator." } });
    }
    next();
  }

  function safeFilename(filename) {
    return filename.replace(/[\r\n\u0000-\u001f\u007f]/g, "_").slice(0, 150) || "download";
  }

  app.get("/api/health", (req, res) => {
    try { db.prepare("SELECT 1").get(); res.json({ status: "ok", app: "TrustVault", database: "ok" }); }
    catch { res.status(503).json({ status: "error", app: "TrustVault", database: "unavailable" }); }
  });

  app.get("/api/auth/csrf", (req, res, next) => {
    req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
    req.session.save((error) => error ? next(error) : res.json({ csrfToken: req.session.csrfToken }));
  });

  app.post("/api/auth/login", loginLimiter, async (req, res, next) => {
    try {
      const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
      const password = typeof req.body?.password === "string" ? req.body.password : "";
      const user = db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(email);
      const passwordMatches = user ? await bcrypt.compare(password, user.password_hash) : false;
      if (!user || !user.is_active || !passwordMatches) {
        audit(req, { action: "auth.login", resourceType: "session", outcome: "failure", details: { reason: "invalid_credentials" } });
        return res.status(401).json({ error: { code: "LOGIN_FAILED", message: "Email or password is incorrect." } });
      }
      await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
      req.session.userId = user.id;
      req.session.csrfToken = crypto.randomBytes(32).toString("base64url");
      await new Promise((resolve, reject) => req.session.save((error) => error ? reject(error) : resolve()));
      audit(req, { actorId: user.id, action: "auth.login", resourceType: "session", outcome: "success" });
      res.json({ user: publicUser(user), csrfToken: req.session.csrfToken });
    } catch (error) { next(error); }
  });

  app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
  app.post("/api/auth/logout", requireAuth, (req, res, next) => {
    const actorId = req.user.id;
    req.session.destroy((error) => {
      if (error) return next(error);
      res.clearCookie("trustvault.sid", { httpOnly: true, secure: secureCookies, sameSite: "strict", path: "/" });
      writeAudit(db, { actorId, action: "auth.logout", resourceType: "session", outcome: "success", ipAddress: req.ip || null });
      res.json({ ok: true });
    });
  });

  app.get("/api/documents", requireAuth, (req, res) => {
    const search = typeof req.query.q === "string" ? req.query.q.trim().slice(0, 100) : "";
    const documents = db.prepare(`
      SELECT d.id, d.owner_id, d.title, d.description, d.original_filename, d.mime_type, d.size_bytes, d.created_at, d.updated_at,
        u.display_name AS owner_name, CASE WHEN d.owner_id = ? THEN 'owner' WHEN ? = 'admin' THEN 'admin' ELSE p.permission END AS access_level
      FROM documents d JOIN users u ON u.id = d.owner_id LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
      WHERE d.deleted_at IS NULL AND (d.owner_id = ? OR p.user_id = ? OR ? = 'admin')
        AND (? = '' OR d.title LIKE ? OR d.original_filename LIKE ? OR d.description LIKE ?)
      ORDER BY d.updated_at DESC LIMIT 200
    `).all(req.user.id, req.user.role, req.user.id, req.user.id, req.user.id, req.user.role, search, `%${search}%`, `%${search}%`, `%${search}%`);
    if (req.user.role === "admin") audit(req, { actorId: req.user.id, action: "admin.document.list", resourceType: "document_collection", outcome: "success", details: { resultCount: documents.length } });
    res.json({ documents: documents.map(({ owner_id, ...document }) => document) });
  });

  app.post("/api/documents", requireAuth, requireUploadRole, upload.single("file"), async (req, res, next) => {
    try {
      const file = req.file;
      if (!file) return res.status(400).json({ error: { code: "FILE_REQUIRED", message: "Choose a document to upload." } });
      const maxUploadMb = Number(db.prepare("SELECT value FROM settings WHERE key = 'max_upload_mb'").get()?.value || 10);
      if (file.size > maxUploadMb * 1024 * 1024) return res.status(413).json({ error: { code: "FILE_TOO_LARGE", message: `File is larger than the current ${maxUploadMb} MB limit.` } });
      const originalName = file.originalname;
      if (originalName.length > 150 || /[\\/\u0000-\u001f\u007f]/.test(originalName) || originalName.includes("..")) {
        return res.status(400).json({ error: { code: "INVALID_FILENAME", message: "Filename contains unsupported path characters." } });
      }
      const extension = path.extname(originalName).toLowerCase();
      const expectedType = ALLOWED_TYPES.get(extension);
      if (!expectedType) return res.status(415).json({ error: { code: "FILE_TYPE_NOT_ALLOWED", message: "Allowed file types are PDF, PNG, JPG, and plain text." } });
      let detectedType;
      if (extension === ".txt") {
        try {
          new TextDecoder("utf-8", { fatal: true }).decode(file.buffer);
          if (file.buffer.includes(0)) throw new Error("Binary text file");
          detectedType = "text/plain";
        } catch { return res.status(415).json({ error: { code: "FILE_CONTENT_INVALID", message: "The file content does not match a supported text file." } }); }
      } else {
        const { fileTypeFromBuffer } = await fileTypeModule;
        detectedType = (await fileTypeFromBuffer(file.buffer))?.mime;
      }
      if (detectedType !== expectedType) return res.status(415).json({ error: { code: "FILE_CONTENT_INVALID", message: "The file content does not match its extension." } });

      const id = crypto.randomUUID();
      const storageKey = crypto.randomUUID();
      const title = typeof req.body.title === "string" && req.body.title.trim() ? req.body.title.trim().slice(0, 120) : path.basename(originalName, extension);
      const description = typeof req.body.description === "string" ? req.body.description.trim().slice(0, 1000) : "";
      await fsPromises.mkdir(absoluteStorageDir, { recursive: true, mode: 0o700 });
      const storagePath = path.join(absoluteStorageDir, storageKey);
      await fsPromises.writeFile(storagePath, file.buffer, { flag: "wx", mode: 0o600 });
      try {
        db.transaction(() => {
          db.prepare(`INSERT INTO documents (id, owner_id, title, description, original_filename, storage_key, mime_type, size_bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(id, req.user.id, title, description, safeFilename(originalName), storageKey, expectedType, file.size);
          audit(req, { actorId: req.user.id, action: "document.upload", resourceType: "document", resourceId: id, outcome: "success", details: { sizeBytes: file.size, mimeType: expectedType } });
        })();
      } catch (error) {
        await fsPromises.unlink(storagePath).catch(() => {});
        throw error;
      }
      res.status(201).json({ document: { id, title, description, original_filename: safeFilename(originalName), mime_type: expectedType, size_bytes: file.size } });
    } catch (error) { next(error); }
  });

  app.get("/api/documents/:id", requireAuth, (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document) return res.status(404).json(accessDenied(req, req.params.id));
    auditAdminDocumentAccess(req, document, "read");
    res.json({ document: { id: document.id, title: document.title, description: document.description, original_filename: document.original_filename, mime_type: document.mime_type, size_bytes: document.size_bytes, created_at: document.created_at, updated_at: document.updated_at, access_level: document.access_level } });
  });

  app.get("/api/documents/:id/preview", requireAuth, async (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document) return res.status(404).json(accessDenied(req, req.params.id));
    if (document.mime_type !== "application/pdf") return res.status(415).json({ error: { code: "PREVIEW_NOT_SUPPORTED", message: "In-browser preview is available for PDF documents only." } });
    auditAdminDocumentAccess(req, document, "preview");
    const storagePath = path.resolve(absoluteStorageDir, document.storage_key);
    if (!storagePath.startsWith(`${absoluteStorageDir}${path.sep}`)) return res.status(404).json(accessDenied(req, req.params.id));
    try { await fsPromises.access(storagePath); }
    catch {
      audit(req, { actorId: req.user.id, action: "document.preview", resourceType: "document", resourceId: document.id, outcome: "failure", details: { reason: "file_missing" } });
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Document file was not found." } });
    }
    audit(req, { actorId: req.user.id, action: "document.preview", resourceType: "document", resourceId: document.id, outcome: "success" });
    const stream = fs.createReadStream(storagePath);
    res.set({
      "Content-Type": "application/pdf",
      "Content-Disposition": 'inline; filename="preview.pdf"',
      "Content-Security-Policy": "sandbox",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "SAMEORIGIN",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Cache-Control": "private, no-store, max-age=0",
      "Pragma": "no-cache",
      "Referrer-Policy": "no-referrer",
    });
    stream.on("error", () => { if (!res.headersSent) res.status(404).json({ error: { code: "NOT_FOUND", message: "Document file was not found." } }); });
    stream.pipe(res);
  });

  app.get("/api/documents/:id/download", requireAuth, async (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document) return res.status(404).json(accessDenied(req, req.params.id));
    auditAdminDocumentAccess(req, document, "download");
    const storagePath = path.resolve(absoluteStorageDir, document.storage_key);
    if (!storagePath.startsWith(`${absoluteStorageDir}${path.sep}`)) return res.status(404).json(accessDenied(req, req.params.id));
    try { await fsPromises.access(storagePath); }
    catch {
      audit(req, { actorId: req.user.id, action: "document.download", resourceType: "document", resourceId: document.id, outcome: "failure", details: { reason: "file_missing" } });
      return res.status(404).json({ error: { code: "NOT_FOUND", message: "Document file was not found." } });
    }
    audit(req, { actorId: req.user.id, action: "document.download", resourceType: "document", resourceId: document.id, outcome: "success" });
    const encodedName = encodeURIComponent(safeFilename(document.original_filename)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
    res.set({ "Content-Type": "application/octet-stream", "X-Content-Type-Options": "nosniff", "Content-Disposition": `attachment; filename="download"; filename*=UTF-8''${encodedName}` });
    const stream = fs.createReadStream(storagePath);
    stream.on("error", () => { if (!res.headersSent) res.status(404).json({ error: { code: "NOT_FOUND", message: "Document file was not found." } }); });
    stream.pipe(res);
  });

  app.patch("/api/documents/:id", requireAuth, (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document || !["owner", "edit", "admin"].includes(document.access_level)) return res.status(404).json(accessDenied(req, req.params.id));
    const { title, description } = req.body || {};
    if (title !== undefined && (typeof title !== "string" || !title.trim() || title.trim().length > 120)) return res.status(400).json({ error: { code: "INVALID_TITLE", message: "Title must be 1 to 120 characters." } });
    if (description !== undefined && (typeof description !== "string" || description.length > 1000)) return res.status(400).json({ error: { code: "INVALID_DESCRIPTION", message: "Description must be 1000 characters or fewer." } });
    if (title === undefined && description === undefined) return res.status(400).json({ error: { code: "NO_CHANGES", message: "Provide a title or description to update." } });
    db.prepare(`UPDATE documents SET title = COALESCE(?, title), description = COALESCE(?, description), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
      .run(title === undefined ? null : title.trim(), description === undefined ? null : description.trim(), document.id);
    auditAdminDocumentAccess(req, document, "edit");
    audit(req, { actorId: req.user.id, action: "document.edit", resourceType: "document", resourceId: document.id, outcome: "success" });
    res.json({ ok: true });
  });

  app.delete("/api/documents/:id", requireAuth, async (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document || !["owner", "admin"].includes(document.access_level)) return res.status(404).json(accessDenied(req, req.params.id));
    const remove = db.transaction(() => {
      db.prepare("UPDATE documents SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").run(document.id);
      db.prepare("DELETE FROM permissions WHERE document_id = ?").run(document.id);
      auditAdminDocumentAccess(req, document, "delete");
      audit(req, { actorId: req.user.id, action: "document.delete", resourceType: "document", resourceId: document.id, outcome: "success" });
    });
    remove();
    await fsPromises.unlink(path.join(absoluteStorageDir, document.storage_key)).catch(() => {});
    res.json({ ok: true });
  });

  app.get("/api/documents/:id/shares", requireAuth, (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document || !["owner", "admin"].includes(document.access_level)) return res.status(404).json(accessDenied(req, req.params.id));
    auditAdminDocumentAccess(req, document, "shares.read");
    const shares = db.prepare(`SELECT p.user_id, p.permission, p.granted_at, u.email, u.display_name
      FROM permissions p JOIN users u ON u.id = p.user_id WHERE p.document_id = ? ORDER BY p.granted_at`).all(document.id);
    res.json({ shares });
  });

  app.put("/api/documents/:id/shares", requireAuth, (req, res) => {
    if (!validId(req.params.id)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document || !["owner", "admin"].includes(document.access_level)) return res.status(404).json(accessDenied(req, req.params.id));
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const permission = req.body?.permission;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !["read", "edit"].includes(permission)) return res.status(400).json({ error: { code: "INVALID_PERMISSION", message: "Choose a registered user and read or edit access." } });
    const target = db.prepare("SELECT id FROM users WHERE email = ? COLLATE NOCASE AND is_active = 1").get(email);
    if (!target) return res.status(404).json({ error: { code: "USER_NOT_FOUND", message: "That active user was not found." } });
    if (target.id === req.user.id) return res.status(400).json({ error: { code: "INVALID_PERMISSION", message: "You already have access to this document." } });
    db.transaction(() => {
      db.prepare(`INSERT INTO permissions (document_id, user_id, permission, granted_by) VALUES (?, ?, ?, ?)
        ON CONFLICT(document_id, user_id) DO UPDATE SET permission = excluded.permission, granted_by = excluded.granted_by, granted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`)
        .run(document.id, target.id, permission, req.user.id);
      auditAdminDocumentAccess(req, document, "permission.grant");
      audit(req, { actorId: req.user.id, action: "permission.grant", resourceType: "document", resourceId: document.id, outcome: "success", details: { userId: target.id, permission } });
    })();
    res.json({ ok: true });
  });

  app.delete("/api/documents/:id/shares/:userId", requireAuth, (req, res) => {
    if (!validId(req.params.id) || !validId(req.params.userId)) return res.status(404).json(accessDenied(req, req.params.id));
    const document = getDocumentAccess(req.params.id, req.user);
    if (!document || !["owner", "admin"].includes(document.access_level)) return res.status(404).json(accessDenied(req, req.params.id));
    const removed = db.prepare("DELETE FROM permissions WHERE document_id = ? AND user_id = ?").run(document.id, req.params.userId);
    if (!removed.changes) return res.status(404).json({ error: { code: "SHARE_NOT_FOUND", message: "That share was not found." } });
    auditAdminDocumentAccess(req, document, "permission.revoke");
    audit(req, { actorId: req.user.id, action: "permission.revoke", resourceType: "document", resourceId: document.id, outcome: "success", details: { userId: req.params.userId } });
    res.json({ ok: true });
  });

  app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
    const users = db.prepare("SELECT id, email, display_name, role, is_active, created_at FROM users ORDER BY created_at DESC").all();
    res.json({ users: users.map((user) => ({ ...publicUser(user), active: Boolean(user.is_active) })) });
  });
  app.post("/api/admin/users", requireAuth, requireAdmin, async (req, res) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    const displayName = typeof req.body?.displayName === "string" ? req.body.displayName.trim() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const role = req.body?.role;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !displayName || displayName.length > 80 || password.length < 12 || password.length > 128 || !["owner", "viewer"].includes(role)) return res.status(400).json({ error: { code: "INVALID_USER", message: "Provide a valid email, name, 12-128 character password, and owner or viewer role." } });
    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    try { db.prepare("INSERT INTO users (id, email, display_name, password_hash, role) VALUES (?, ?, ?, ?, ?)").run(id, email, displayName, passwordHash, role); }
    catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") return res.status(409).json({ error: { code: "EMAIL_IN_USE", message: "An account with that email already exists." } });
      throw error;
    }
    audit(req, { actorId: req.user.id, action: "admin.user.create", resourceType: "user", resourceId: id, outcome: "success", details: { role } });
    res.status(201).json({ user: publicUser(userById.get(id)) });
  });
  app.patch("/api/admin/users/:id", requireAuth, requireAdmin, (req, res) => {
    const active = req.body?.active;
    if (!validId(req.params.id) || typeof active !== "boolean") return res.status(400).json({ error: { code: "INVALID_USER_UPDATE", message: "Provide a user ID and an active true/false value." } });
    if (req.params.id === req.user.id && !active) return res.status(400).json({ error: { code: "CANNOT_DISABLE_SELF", message: "You cannot disable your own account." } });
    const updated = db.prepare("UPDATE users SET is_active = ? WHERE id = ?").run(active ? 1 : 0, req.params.id);
    if (!updated.changes) return res.status(404).json({ error: { code: "USER_NOT_FOUND", message: "User was not found." } });
    audit(req, { actorId: req.user.id, action: "admin.user.status", resourceType: "user", resourceId: req.params.id, outcome: "success", details: { active } });
    res.json({ ok: true });
  });

  app.get("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
    const settings = Object.fromEntries(db.prepare("SELECT key, value FROM settings").all().map(({ key, value }) => [key, value]));
    res.json({ settings: { uploadsEnabled: settings.uploads_enabled === "true", maxUploadMb: Number(settings.max_upload_mb) } });
  });
  app.patch("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
    const { uploadsEnabled, maxUploadMb } = req.body || {};
    if (typeof uploadsEnabled !== "boolean" || !Number.isInteger(maxUploadMb) || maxUploadMb < 1 || maxUploadMb > 10) return res.status(400).json({ error: { code: "INVALID_SETTINGS", message: "Choose whether uploads are enabled and a 1-10 MB upload limit." } });
    db.transaction(() => {
      db.prepare("UPDATE settings SET value = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE key = 'uploads_enabled'").run(String(uploadsEnabled));
      db.prepare("UPDATE settings SET value = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE key = 'max_upload_mb'").run(String(maxUploadMb));
      audit(req, { actorId: req.user.id, action: "admin.settings.update", resourceType: "settings", outcome: "success", details: { uploadsEnabled, maxUploadMb } });
    })();
    res.json({ settings: { uploadsEnabled, maxUploadMb } });
  });

  app.get("/api/admin/audit", requireAuth, requireAdmin, (req, res) => {
    const requested = Number(req.query.limit);
    const limit = Number.isInteger(requested) ? Math.max(1, Math.min(requested, 200)) : 100;
    const events = db.prepare(`SELECT a.id, a.occurred_at, a.actor_id, u.display_name AS actor_name, a.action, a.resource_type, a.resource_id, a.outcome, a.details_json
      FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id ORDER BY a.id DESC LIMIT ?`).all(limit);
    res.json({ events: events.map(({ details_json, ...event }) => ({ ...event, details: JSON.parse(details_json) })) });
  });
  app.get("/api/audit/mine", requireAuth, (req, res) => {
    const events = db.prepare(`SELECT id, occurred_at, action, resource_type, resource_id, outcome, details_json FROM audit_events
      WHERE actor_id = ? ORDER BY id DESC LIMIT 50`).all(req.user.id);
    res.json({ events: events.map(({ details_json, ...event }) => ({ ...event, details: JSON.parse(details_json) })) });
  });

  app.use("/", express.static(path.join(__dirname, "..", "public"), { index: "index.html", fallthrough: true }));
  app.use("/api", (req, res) => res.status(404).json({ error: { code: "NOT_FOUND", message: "API endpoint was not found." } }));
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error instanceof multer.MulterError) {
      const status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      return res.status(status).json({ error: { code: error.code, message: status === 413 ? "File is larger than the 10 MB limit." : "Upload could not be processed." } });
    }
    if (error.status === 400 && error.type === "entity.parse.failed") return res.status(400).json({ error: { code: "INVALID_JSON", message: "Request body must be valid JSON." } });
    console.error("TrustVault request failed:", error.message);
    res.status(500).json({ error: { code: "INTERNAL_ERROR", message: "The request could not be completed." } });
  });
  return app;
}

module.exports = { createApp, FILE_LIMIT, ALLOWED_TYPES, getLoginRateLimitOptions };