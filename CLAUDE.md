# Scripting repo - instructions for Claude

- Every new or edited PowerShell script must follow STANDARDS.md. Read it first.
  Rule numbers there are permanent IDs cited from script headers; never renumber.
- When editing an existing script: bump the version (file name, header, and
  `$ScriptVersion`), add a `vX.Y changes:` block to the header, and keep the
  old file unless told otherwise.
- Write `.ps1` files with CRLF line endings and a UTF-8 BOM.
- Do not reorganize folders yet - the layout is still undecided (see README.md).
