# TrustVault

TrustVault is a small secure document-sharing app built with Node.js, Express, SQLite, and plain HTML/CSS/JavaScript. It demonstrates server-side authorization and a practical audit trail; it is a learning project, not a certified document vault.

## Features

- Admin, Owner, and Viewer roles with server-side permission checks.
- Passwords hashed with bcryptjs; sessions stored in SQLite and regenerated at login.
- CSRF checks for state-changing requests, Helmet headers, and request/login rate limits.
- Private file uploads with generated storage IDs, a 10 MB maximum, and PDF, PNG, JPG/JPEG, or UTF-8 TXT content checks.
- Per-document read/edit grants, immediate revocation, in-browser PDF preview, separate safe attachment downloads, search, and details.
- Owner/admin account controls, persistent upload settings, personal activity, and admin audit view.
- Node's built-in test runner exercises the real HTTP routes with temporary databases.

## Requirements

- Node.js 22 or later and npm.
- On Windows, the installed `better-sqlite3` package needs its supported prebuilt binary or a native C++ build toolchain.

## Install and run locally

From the TrustVault project directory:

```powershell
npm install
Copy-Item .env.example .env
```

Edit `.env` locally. Replace `SESSION_SECRET` with a private random value of at least 32 characters. Keep `COOKIE_SECURE=false` only for local HTTP development. Do not commit `.env`.

Keep `NODE_ENV=development` for the local app: this uses a bounded login limit of 30 attempts per minute. Production remains at 10 attempts per 15 minutes. Login limiting uses an in-memory store, so a local server restart clears its counter without touching SQLite data.

For a quick local demo on a clean database, run:

```powershell
npm run seed:dev
npm start
```

The seed command creates disposable `admin@example.test`, `owner@example.test`, and `viewer@example.test` accounts with randomly generated passwords, prints those passwords once, and refuses to run in production or when a user already exists. Store or discard the printed credentials safely. To create only your own first admin instead, leave the database empty, set `ADMIN_EMAIL`, `ADMIN_NAME`, and `ADMIN_PASSWORD` in `.env`, then run:

```powershell
npm run setup:admin
npm start
```

The bootstrap password must be 12-128 characters. The setup command creates only the first admin; the admin can add Owner and Viewer accounts from People. Remove the `ADMIN_PASSWORD` value from `.env` after setup.

### Recover a forgotten local Owner password

Seeded passwords are random and only their bcrypt hashes are stored, so the original password cannot be displayed or recovered. To set a new one without resetting the database, stop the server with Ctrl+C, then from the project directory run:

```powershell
$env:RESET_OWNER_PASSWORD = Read-Host "New Owner password (12-128 characters)"
npm run reset:owner
Remove-Item Env:RESET_OWNER_PASSWORD
npm start
```

The script targets `owner@example.test` by default. It updates only that account's password hash, expires sessions belonging to that Owner, and records the recovery in the audit trail. It does not change account IDs, documents, shares, audit history, or other accounts. To target a different local Owner account, set `RESET_OWNER_EMAIL` before running the command. Never paste the password into a command argument or commit it to a file.

For a forgotten Viewer password, use the parallel `reset:viewer` command and `RESET_VIEWER_PASSWORD` variable with the same masked `Read-Host -AsSecureString` PowerShell pattern. It targets `viewer@example.test` by default, checks that the matching account has the Viewer role, and preserves all sessions as requested. It changes only that Viewer password hash and adds one audit event.

Open `http://localhost:3000`. The database is created at `data/trustvault.sqlite`, and files go to `uploads/`; both are private local folders, not static web content. Health check: `http://localhost:3000/api/health`.

## Tests

```powershell
npm test
```

Tests use temporary directories and delete them afterward. They do not seed or modify your local `data/` database.

## Architecture

- `server.js` loads local environment values, validates the session secret, opens SQLite, and starts Express.
- `src/db.js` owns tables, the SQLite session store, and the trusted audit writer.
- `src/app.js` owns HTTP routes, validation, authentication, authorization, and private file handling.
- `src/config.js` resolves database/upload paths; `public/` contains the browser UI only.
- `scripts/setup-admin.js` bootstraps the first admin. `scripts/seed-dev.js` creates disposable development accounts.
- `test/security.test.js` starts an isolated app and makes real HTTP requests.

Role checks are made on the server, not inferred from hidden buttons. Owners manage their own documents and shares. Viewers can access only explicitly shared files; `read` allows viewing/downloading, and `edit` also allows changing document title/notes. Only the document owner or an Admin can grant/revoke access or delete it. Admins can manage all documents, users, upload settings, and audit history; their access to another person's document is recorded.

## API overview

- `GET /api/health`, `GET /api/auth/csrf`, `POST /api/auth/login`, `GET /api/auth/me`, `POST /api/auth/logout`
- `GET /api/documents?q=...`, `POST /api/documents`, `GET/PATCH/DELETE /api/documents/:id`
- `GET /api/documents/:id/preview` (authorized PDFs, inline/no-store), `GET /api/documents/:id/download` (authorized attachment), `GET/PUT /api/documents/:id/shares`, `DELETE /api/documents/:id/shares/:userId`
- `GET /api/audit/mine`; Admin-only `GET /api/admin/audit`, `/api/admin/users`, `/api/admin/settings`; user create/status and settings updates use POST/PATCH.

Errors use `{ "error": { "code": "...", "message": "..." } }`. Private document IDs are not sufficient to access a file: every request checks the current database owner/share record. Unknown or unauthorized document IDs return the same not-found response.

## Audit trail limits

The server creates audit rows for login outcomes, access denials, uploads/downloads, edits/deletes, permission changes, and admin actions. Ordinary HTTP users have no audit write/delete route. Passwords, session IDs, and file contents are never written into the audit details. The audit table is not cryptographically tamper-evident: a person with direct database/filesystem access or a compromised server can alter it. Failed attempts are recorded when they reach an instrumented route; upstream network failures and platform logs are outside this app's audit guarantee.

## Deployment (Render example)

1. Create a **private** GitHub repository. Review `git status` and `git diff` before committing; never add `.env`, `data/`, `uploads/`, or real documents. Suggested checkpoints: `feat: add sqlite auth and role checks`, `feat: add private document sharing and audit`, `feat: connect responsive dashboard and security tests`, `docs: add setup and deployment guide`.
2. Create a Render Web Service from that private repo. Build command: `npm ci`. Start command: `npm start`. Health-check path: `/api/health`.
3. Set `NODE_ENV=production`, `SESSION_SECRET` (a fresh random secret), `COOKIE_SECURE=true`, `TRUST_PROXY=true`, `DATABASE_PATH=/var/data/trustvault/trustvault.sqlite`, and `UPLOAD_DIR=/var/data/trustvault/uploads` in the service environment.
4. Attach a persistent disk mounted at `/var/data/trustvault` (Render disks are generally a paid-plan feature). Keep the SQLite database and uploaded files on that same persistent disk. Without persistent storage, deploy/restart can lose both. SQLite is intended for one app instance on a local disk; do not scale this setup to multiple instances or put SQLite on a shared network filesystem.
5. Create the first admin using the provider's one-off shell with `ADMIN_EMAIL`, `ADMIN_NAME`, and `ADMIN_PASSWORD` set privately, then run `npm run setup:admin`. Remove the password variable afterward. Never put it in Git or a build command.
6. Wait for the provider to report a successful deploy, then test the actual URL in a private/incognito browser window: load `/api/health`, sign in, upload a harmless sample, share it with a second account, verify download, revoke, and verify the second account is denied. Repeat on another device if available. A local test run does not mean the app is deployed.

For a production service, configure TLS at the host, backups for both the database and file directory, restore drills, dependency updates, monitoring, and an operational account-recovery process. This project does not implement malware scanning, email verification, password reset, SSO/MFA, encryption-at-rest key management, or immutable external audit storage.