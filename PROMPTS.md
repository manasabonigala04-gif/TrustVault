# AI Work Log

Entries below describe work and checks that actually happened on 2026-10-22. Test results refer to local execution only; no deployment or Git commit was performed.

## 2026-10-22 — Inspect the initialized project

- **Task:** Inspect the existing TrustVault folder, package, and server before implementing.
- **Decision:** Kept the existing Express entry point and selected SQLite with `better-sqlite3`; verified the installed Node runtime and loaded the SQLite driver and `file-type` detector.
- **Verification/change:** The dependency smoke test printed SQLite `3.53.4` and confirmed `fileTypeFromBuffer` is available. Existing empty subfolders were reused; no nested project was created.

## 2026-10-22 — Enforce upload content and path checks

- **Task:** Reject unsupported document extensions, mismatched content, and traversal filenames.
- **Mistake caught:** The first integration run showed Multer's default path handling had reduced `../secret.pdf` to a basename before application validation, so the route accepted a filename the test expected to reject.
- **Verification/change:** Enabled Multer `preservePath`, kept explicit slash/backslash/dot-dot rejection, then reran the suite. The final test checks executable extension, fake PDF content, and traversal name.

## 2026-10-22 — Exercise authentication and authorization

- **Task:** Verify server-side sessions and document access, rather than only hiding UI controls.
- **Verification/change:** Node's test runner used separate session cookies and a temporary SQLite database to check unauthenticated denial, session regeneration, logout invalidation, private-ID guessing, shared download, and access denial immediately after revoke.

## 2026-10-22 — Add and verify administrator controls

- **Task:** Add persistent upload settings and explicit administrative document access.
- **Verification/change:** Integration tests confirmed a regular Owner cannot read admin settings, an Admin can persist the upload limit/disabled state, the server rejects a subsequent upload, and cross-owner Admin document access is audited.

## 2026-10-22 — Recover from local cloud-folder sync

- **Task:** Continue after the project source stopped appearing in the VS Code file view.
- **Mistake caught:** The first fresh test command ran the package's old placeholder script, and workspace search showed the authored source folders empty.
- **Verification/change:** PowerShell confirmed the project directories were OneDrive reparse-point placeholders. Restored the authored source, package scripts, and test files without altering project data, then reran `npm test`: 11 passed, 0 failed. Deployment and browser-on-another-device checks have not been performed.

## 2026-10-22 — Verify the browser workflow

- **Task:** Exercise the actual login, dashboard, upload, and delete interactions in the local browser.
- **Mistake caught:** The first browser sign-in exposed that an async event handler used `event.currentTarget` after an `await`, when the browser had already cleared it. The same pattern existed in the upload, sharing, and account forms.
- **Verification/change:** Captured form elements before awaiting requests, repeated browser login, uploaded a tiny generated PDF, and deleted it from the UI. Confirmed the dashboard displayed the new row and returned to its empty state. Final `npm test`: 12 passed, 0 failed. The app is local only; deployment and a second-device test remain undone.

## 2026-10-22 — Recover a forgotten demo password safely

- **Task:** Inspect local demo-account setup and database state without resetting or deleting populated data.
- **Verification/change:** Read the seed/bootstrap implementation and queried SQLite in read-only mode for account names/roles and aggregate table counts only. Confirmed demo passwords are random and unrecoverable from bcrypt hashes, then added a targeted Owner password-reset command and a test proving document/share records, other accounts, and other sessions remain intact. The command has not been run against the populated local database.

## 2026-10-22 — Fix local login throttling

- **Task:** Resolve a 429 after the Owner password had been reset without weakening production throttling or resetting the database.
- **Verification/change:** Confirmed the original policy was 10 login POSTs per IP per 15 minutes, with an in-memory counter. Added a bounded 30-per-minute policy only when `NODE_ENV=development`, preserved 10 per 15 minutes otherwise, and tested both configurations plus the active development response header. Restarted the local process; the database was not deleted or reset.

## 2026-10-22 — Recover the Viewer password

- **Task:** Provide password recovery for only `viewer@example.test`, preserving sessions as requested.
- **Verification/change:** Read the existing Owner reset flow and queried only account/role/status plus aggregate database counts in read-only mode. Added a role-checked Viewer reset script and a test that verifies all sessions, documents, shares, and other account hashes remain unchanged. The new command has not been run against the populated local database.