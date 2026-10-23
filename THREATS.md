# TrustVault Threat Model

This is a beginner-oriented threat model for the current demo build. It describes the protections implemented in this code, not a certification or guarantee against a compromised host.

## Assets

- Private uploaded document bytes and their metadata.
- User identity, password hashes, active/disabled account state, and share permissions.
- Session cookies and server-side sessions.
- Audit events and administrator-managed settings.
- Availability and integrity of the SQLite database and private upload directory.

## Security boundaries

- The browser is untrusted. It can change IDs, form values, roles, and requests; server-side routes validate and authorize every protected operation.
- `public/` is static web content. Uploaded bytes are stored in `uploads/` or `UPLOAD_DIR`, outside the public directory, and are only served by the authorized download route.
- The application process and its database/filesystem credentials are trusted. Host administrators and anyone who can read/modify those files are outside the app's authorization boundary.
- SQLite session storage keeps sessions across restarts on the same persistent disk. Deployment platform, TLS termination, backups, and disk durability are operational boundaries.

## Threats and mitigations

| Threat / scenario | Mitigation in this app | Residual risk |
| --- | --- | --- |
| Guess another document ID or alter a URL | UUID IDs plus a database ownership/share check on list, detail, edit, download, share, revoke, and delete routes; unauthorized reads use a not-found response | A server/database defect could still bypass a check; tests cover key cases, not every possible future route |
| Use a stale link after share revocation | Permission rows are checked on each request, not encoded in long-lived links; revocation is immediate | A download already completed or bytes already saved cannot be recalled |
| Forge a role in browser JSON | Role comes from the active user row in SQLite; route middleware checks it on the server | Database or process compromise can alter roles |
| Steal a password by reading storage/logs | bcryptjs hashes passwords; password fields and hashes are not returned or audited; login errors are generic | Weak/reused user passwords and host-level compromise remain risks; no MFA/password reset |
| Reuse a pre-login session ID | Express session is regenerated after successful login; cookies are HttpOnly, SameSite=Strict, and Secure in production | XSS, stolen browser/device access, or misconfigured TLS/proxy can still compromise sessions |
| Cross-site request forgery | State-changing API requests require a random session-bound CSRF header token; SameSite cookies add defense | Same-origin script injection can access the CSRF token; there is no dedicated CSP hardening review |
| Guess passwords repeatedly | Login endpoint has a dedicated rate limit and generic failure message; failed attempts are audited | In-memory rate-limit counters reset on restart and are not shared across instances |
| Upload a script, disguised executable, or path traversal name | 10 MB in-memory limit, extension allow-list (PDF/PNG/JPG/TXT), file signature or UTF-8 checks, preserved/rejected path separators, generated storage keys, private directory | No malware scanning, archive support, image re-encoding, or antivirus; treat all uploads as untrusted |
| Directly request a private file from a static URL | Uploads are outside `public/`; only a permission-checked attachment route reads them; responses use `nosniff` and attachment disposition | A person with host filesystem access can read files directly |
| Tamper with audit events through HTTP | There are no client-supplied event fields or audit edit/delete routes; server code writes events; ordinary accounts cannot read global admin history | Audit is not cryptographically signed or immutable against DB/host administrators; logging can fail if storage fails |
| Learn file paths or contents from logs/errors | Safe JSON errors, generated identifiers, and audit details omit filesystem paths and file contents | Deployment infrastructure may collect its own request logs; review host logging/retention settings |
| Lose files on deploy or disk failure | Configurable storage paths and documented persistent-disk setup | Ephemeral storage loses files/database; the app does not make backups or restore them automatically |

## Role rules

- **Admin:** manages accounts and upload settings, sees global audit records, and can manage all documents. Access to someone else's document is itself audited.
- **Owner:** manages documents they uploaded, including metadata, shares, revocation, and deletion.
- **Viewer:** can access only explicitly shared documents. `read` grants view/download; `edit` also grants metadata edits. Neither allows onward sharing or deletion.

## Audit scope and sensitive fields

The server records actor (where known), UTC timestamp, action, resource ID/type, outcome, and limited context. It never stores passwords, session tokens, or document bytes in audit details. IP address is stored for operational investigation. Invalid login records deliberately omit the submitted email to reduce unnecessary personal data. Audit data is application-level and append-only through the public API, not a tamper-proof ledger.

## Before real-world use

Use a managed identity provider or add MFA, password recovery, email verification, malware scanning, encrypted backups, key management, external append-only audit export, tested restore procedures, security monitoring, and a professional review. Restrict filesystem access and run the service as a non-root account. Do not host sensitive documents until these controls and legal/privacy needs are assessed.