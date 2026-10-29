# Development status

This repository contains work in progress. It is not a production-ready endpoint
management release, and source publication does not authorize endpoint deployment.

Implemented foundations include scoped enrollment and permissions, optional server
module registration, signed catalogs and device selection, an artifact service,
dependency planning, native package verification and lifecycle supervision, a
Windows bootstrap service and protected enrollment storage, a separate native
inventory host, and server/console adaptations for desktop policies, asset
management, Falcon, EMA and recovery-key escrow.

Windows Update now has a separate native host for exact scan/install commands,
with renewable execution leases and chunked results. The bootstrap stays responsive
while the host works. Selected packages use short-lived download capabilities,
and artifacts can be served from the server computer behind TLS ingress.
Windows Search indexing now has its own downloadable host and console receipts
for catalog/service status, configured crawl rules, approved enable/disable and
explicit service-stop fallback pause/resume. Timed pause, custom rule changes and
baseline restoration remain open.
User-session discovery and explicit-logon WinGet checks/pinned user upgrades now
have separate native hosts. Real standard-user execution and session-switch
acceptance remain open. Deployment and recovery compatibility providers remain
migration input. Remaining native host extraction, macOS installation, file transfer,
clipboard synchronization, remote access, independent recovery and end-to-end
acceptance remain unfinished. A registered module is not evidence of a working
endpoint feature.

The server is intended to host the complete catalog. Each installer is exclusively
a thin bootstrap that downloads selected modules and exact dependencies. No endpoint
release is accepted until clean installation, selection, revocation, interruption,
rollback, session isolation and recovery tests pass on the target platforms.

The 30 October 2026 local verification includes successful TypeScript, Go and
Windows compatibility builds, native conformance checks and PowerShell parsing.
The Windows compatibility suite passed 73 tests and skipped 18 requiring elevated
storage access locally; Windows CI passes all 101 expanded compatibility cases with
no skips, and the native suite passes on Windows, Linux and macOS. The full
control-plane suite includes native dispatch, indexing admission and scope-filtered audit tests. Dispatch and
release tests exercise actual native custody, signed publication, scoped selection
and enrollment. Isolated PostgreSQL 18.6 runs use restricted runtime roles and
cleans up its owned server. Native Windows secret-storage tests require elevation
and fail rather than skip in Windows CI. At commit `e2719dd`, both verification
workflows pass. Windows CI installs a signed bootstrap as a SYSTEM service, proves
zero feature downloads with empty selection, downloads Inventory only when selected,
restarts with Inventory enabled without another download, and checks deselection
and revocation. Selected Indexing download and actual read-only command execution
also pass in that pilot. The next increment adds session discovery and explicit
rejection of an unavailable selected logon. Remaining provider implementation and live endpoint
acceptance are still required.
