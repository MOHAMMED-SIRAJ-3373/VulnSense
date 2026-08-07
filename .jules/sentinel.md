## 2026-08-07 - Path Traversal in File Serving Route
**Vulnerability:** The `/api/models/<filename>` route accepted user input for the filename and concatenated it with the `ROOT` path using `os.path.join` without sanitization. This allowed attackers to access arbitrary files on the system using `../` (path traversal).
**Learning:** `os.path.join` is dangerous if any of its inputs are unsanitized user-provided paths. In web endpoints that fetch files by name, unsanitized parameters expose the local filesystem.
**Prevention:** Always use a secure library method like `werkzeug.utils.secure_filename` to sanitize the filename parameter before utilizing it in file operations.
