# Retained Sentry integration

The 30 October 2026 instruction retains Sentry's complete computer-management scope in One Control. CRM, Android management, AMAPI and the Android companion remain excluded, as explicitly confirmed. The existing seven-phase One Control scope remains active, including features beyond either Sentry repository.

## Sources and custody

The repositories were located and their main revisions read directly through Git:

| Repository | Pinned revision | Relationship |
| --- | --- | --- |
| [Sentry V2](https://github.com/chai-in/sentry-v2) | `b509d0939768aec9698bd3b8ae4287f3fe50d6f2` | Existing Phase 1 foundation; same revision as `sentry-v2-import.json`. |
| [TIBCON Sentry](https://github.com/tibcon-git/tibcon-sentry) | `30799e4e2e57574521ddc628b338814ac2041bf8` | Desktop policy, agent, Falcon, EMA and asset-management source. |

The machine-readable [provenance manifest](sentry-integration.json) pins source Git objects and SHA-256 hashes for 66 relevant files. The legacy archived revision is `fdd8e206e39c0046b316c7f838e8f128684c71dc`. Its difference from current main is 12 files, chiefly licensing/documentation and build metadata, rather than new desktop implementation. No inherited setup or deployment script was run. The transfer archive, extracted snapshot, Git bundles and private-state material were not modified.

TIBCON-owned source at the selected revision is GPL-3.0-only. The [license text](../third_party/licenses/TIBCON-Sentry-GPL-3.0.txt) is preserved exactly. Adapted policy and Falcon files carry SPDX notices; source-to-target relationships are in the provenance manifest. No upstream credentials, SSO database bindings, signing identities, deployments or queued operations are imported.

## Complete feature scope

The [route map](sentry-route-map.tsv) records 99 upstream desktop, inventory, Falcon and EMA route declarations, their exact source location, retained feature and acceptance requirement. The CRM trust route is explicitly excluded. Mobile/companion/PubSub routes are outside the retained product. Mixed desktop/asset functions retain only their desktop/company meaning; mobile identifiers and commands are not reintroduced.

The acceptance ledger adds `OC-SENTRY-001` through `OC-SENTRY-028`, retaining:

- Policy library/templates, immutable history, clone/retire/rollback, groups, device overrides, default precedence, target previews and canary rollout.
- Inventory, installed applications, update and encryption posture; canonical native/Falcon/EMA identity reconciliation.
- Optional application allow/deny, category/domain filtering and Gateway synchronization; BitLocker lifecycle and encrypted key escrow; supported USB/Falcon Device Control.
- Optional company activity and screenshots, visible session notice/indicator, app exclusions, audited viewing and explicitly chosen retention.
- Typed remote actions, independent approval, tamper reporting, time-limited uninstall, signed enrollment/deployment, agent version rollout and independent recovery.
- Falcon hosts/assets/apps/groups/detections/incidents/vulnerabilities/ZTA/policies, scoped sync/webhooks, containment/release and bounded RTR deployment/recovery/diagnostics.
- Independent EMA inventory, verified endpoint mapping, AMT/CIRA power/KVM, deployment packages/group queues/runner progress/cancellation.
- Company employee/asset inventory, assignments, unassigned computers and offboarding.
- Corresponding console workflows, authenticated reporting, retention and source provenance.

Retaining a requirement does not certify implementation or runtime parity. Every route is marked `retained-not-parity-verified` or `excluded`; source counts are not feature-completion counts. The ledger identifies remaining implementation explicitly.

## Implemented in the active source

`desktop-policies` is an optional server module requiring `desktop.policy` in the scope permission ceiling. It shares the existing ModuleControl grant, scope lock and version-CAS boundary. Policy mutations, immutable history and audit commit together; IDs are scope-local. Retired policy IDs cannot silently acquire a new history. All policy versions are decimal strings and rollback creates a later version. Content SHA-256 identifies configuration, not signature authority.

The console has a Desktop policies panel for accessible scopes, explicit scope creation/module enablement, templates, form editing, history/rollback, group management, default/device/group assignment, effective-policy preview and canary controls. Scope-owner grants are required to expand the permission ceiling. A configuration-only operator can enable the module only inside an already granted ceiling.

Policy precedence is device override, then primary group, then an explicitly configured default. New scopes have no default. Assignments bind the current native enrollment, so replacement enrollment does not silently inherit an old device override. Group or assignment/default changes abort staged canaries for the scope. Disabling the module also aborts active canaries.

Canary staging records a candidate digest, base version and exact target enrollments. Promotion requires verified observations for that candidate from all still-live target enrollments. No administrator endpoint can fabricate those observations. Native signed health ingestion is unfinished, so newly staged canaries currently cannot advance to accepted promotion. The UI and API report endpoint execution as not connected.

Policy authoring covers app lists, web categories/domains, BitLocker modes/rotation/encryption settings, USB storage, Windows Update, activity/inventory/screenshots, cadence, exclusions and notice. Monitoring and enforcement are off/unmanaged by default. Activity/screenshots are company-only and require an explicit notice and retention selection. Templates are offered for manual selection and never auto-assigned. Policy selection does not grant module permissions, install payloads or invoke endpoint operations. Suspension/decryption must be explicitly confirmed again on rollback, clone or promotion.

Falcon now has bounded scoped read routes and console pagination for hosts, assets, applications, groups, alerts, incidents, Spotlight vulnerabilities and prevention/sensor/device-control policies, plus host detail and ZTA. Optional falcon-sync and falcon-events modules add paged cache refresh, explicitly configured scheduled refresh and HMAC-authenticated webhook receipts. Cache scans retain earlier observations until a complete pass; external observations never establish native identity. API errors distinguish missing scope, unlicensed resources, rate limiting and incomplete results. Falcon and EMA console requests now include selected management scope; server credentials remain bound to the explicitly configured scope. External data stays labelled as source observations, never automatic native device identity.

The asset-management module provides company employees, asset records, assignments, metadata offboarding and explicit source links. Native links verify current enrollment; Falcon/EMA references remain operator-recorded and cannot authorize command targeting. Offboarding returns assigned assets for follow-up and does not revoke external identity or wipe devices.

Native modules and Native inventory console panels expose catalog import/platform selection and source-labelled reports. These paths require explicit module enablement. They do not activate inherited deployment accounts, scripts or queued work.

## Storage and restoration

Ordered migrations now extend through v9: desktop policies, company assets, Falcon data, native signed publication, observations, command receipts and encrypted recovery-key escrow. Backup manifests retain each version with exact inventories. See [server authority](server-module-authority.md) for the table and restore boundaries.

Restoration preserves policy/history/group/assignment evidence but quarantines authority, revokes credentials/enrollments/grants, disables modules and aborts pending/healthy policy canaries before publishing the destination. Observed target records are retained as dated evidence, never replayed as fresh acceptance. No ordinary route restores quarantined authority.

## Remaining work and evidence boundary

The full Sentry feature set is not operational yet. Native catalog/policy/freshness signing and transport, heartbeat/inventory sequence receipts, company asset/employee workflows and Falcon sync/webhooks are implemented in source. Protected installation hookup, verified module activation, native client command execution and signed desktop enforcement settings remain open. So do Windows application/BitLocker/USB/monitoring providers and screenshot storage, Gateway synchronization, Falcon typed mutations and EMA deployment/power/KVM. The old Rust service is migration input, not a second co-running full policy agent or a thin-agent release.

Type checking and source formatting were used as build feedback. New behavioral tests and defensive verification were deferred under the latest workspace instruction until functionality is built. Older migration/PostgreSQL results predate these additions and do not validate them. Before any implementation commit, the required full pnpm, locked Windows, PowerShell, real-PostgreSQL and protected Windows CI gates still apply. No production system or endpoint was configured or changed during this integration.

Encrypted key escrow and scoped audited reveal are now in source; see [recovery-key escrow](recovery-key-escrow.md). Native server dispatch records exact enrollment admission, creator/approver grants and a client-owned claim token hash. Late terminal evidence does not replace an uncertain job outcome. Client execution and real acceptance remain open.

## Optional inventory host and scope controls

The optional native inventory executable now has bounded activation/request IPC and collection-time policy binding through the report outbox. Its candidate package is built separately from the bootstrap. The console adds scope creation, permission ceilings, selected server roots and issuer/subject grant management; publication retries retain the same frozen request identity. These paths compile, but behavioral, protected-service and endpoint acceptance remain open. See [inventory host](native-inventory-host.md) and [server authority](server-module-authority.md).
