# Snapshot and quarantined restore design

The import preserves the PGlite snapshot engine, quarantined restoration rules and bounded IPC helpers. The former persistent SYSTEM-task launcher and its dependent administration wrappers remain archived. There is no operational backup/restore command for a persistent One Control backend in phase 1.

## Preserved implementation

`apps/control-plane/src/local-backup.ts` captures a consistent embedded-database snapshot and verifies its manifest and archive. `scripts/lib/local-poc-backup.mjs` validates request identity, runtime identity and a bounded live window. The API child helper accepts requests only through its inherited IPC channel. It is exercised under an ordinary user by an isolated process test.

A restored database preserves history but quarantines pending or uncertain operations and invalidates restored enrollment/device credentials. Restoration never starts a runtime or replays mutations. Invalid or incomplete evidence stays available for diagnosis.

## Verification

The isolated API-process test verifies current-run request handling, duplicate suppression, IPC lifetime and clean shutdown. Database tests verify snapshot integrity, identity, preservation and quarantine. See current phase 1 results.

## Deployment work

A persistent backend needs a protected supervisor, immutable executable/dependency inputs, authorized backup storage and explicit recovery procedures. Production PostgreSQL needs its own database backup and point-in-time recovery system. PGlite snapshots are not a PostgreSQL migration or production backup format.
