# One Control development

All features are optional modules in modules/<id>. Follow docs/module-architecture.md and docs/module-layout.md. Keep the bootstrap free of feature engines; download only selected modules and exact dependencies from the server. Keep planning, signature verification, download, activation and collection separate.

CRM, Android, AMAPI and the Android companion are excluded. Private deployment modules, credentials and archives do not belong in this repository. Preserve third-party notices. Do not add author attribution without an explicit request.

Preserve separate SYSTEM, user-session, recovery, server, artifact and console trust boundaries. Unknown operation outcomes must never trigger automatic replay. Endpoint acceptance requires actual platform tests, not compilation alone.

Before committing implementation changes, run pnpm check, locked Windows solution restore/build/tests and scripts/check-powershell.ps1. Coordination changes also require real PostgreSQL transaction checks. Protected Windows storage tests must run elevated in Windows CI; local skips are not equivalent coverage.
