# Development status

This repository contains work in progress. It is not a production-ready endpoint
management release, and source publication does not authorize endpoint deployment.

Implemented foundations include scoped enrollment and permissions, optional server
module registration, signed catalogs and device selection, an artifact service,
dependency planning, native package verification and lifecycle supervision, a
Windows bootstrap service and protected enrollment storage, a separate native
inventory host, and server/console adaptations for desktop policies, asset
management, Falcon, EMA and recovery-key escrow.

Windows update, application update, deployment, recovery and user-session providers
have been moved into feature folders. Their imported compatibility assembly remains
migration input. Full native host extraction, macOS installation, file transfer,
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
storage access. The full control-plane suite passed 133 of 143 tests; ten failures
remain in older dispatch, release and integration fixtures after scoped enrollment
became required. An isolated PostgreSQL 18.6 run passed 69 of 81 tests and cleaned
up its owned server. These failures are not waived for deployment. Elevated Windows
storage coverage, remaining provider implementation and live endpoint acceptance
are still required.
