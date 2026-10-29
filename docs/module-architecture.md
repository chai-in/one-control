# Thin agent and modular features

Every One Control feature is an independently versioned optional module. Shared dependencies provide identity, secure transport, policy distribution, audit, storage, cryptography and platform hosting. Feature code depends on these contracts; the core does not depend on feature implementations. Enabling a feature selects its modules and dependencies, rather than installing the entire product.

## Minimal installation

The bootstrap contains device enrollment, protected device keys, authenticated configuration retrieval, signed catalog verification, dependency resolution, a verified package downloader, module lifecycle supervision and recovery. It does not bundle inventory collectors, update providers, remote desktop engines, clipboard monitoring or file-transfer engines. A native bootstrap can obtain an approved shared runtime when a selected module needs it; the choice and measured installer size are a feasibility gate. Framework-dependent payload size alone is not proof of a thin install if a large runtime was silently preinstalled.

The current imported .NET service is a migration foundation. Its providers now live in feature folders and must become separately downloadable hosts before release. The module package supplies dependency-planning contracts and tests. The [native package library](native-packages.md) verifies publisher-attested bytes and stages inert files. Its opaque receipt does not grant execution authority. The separate generation owner journals accepted authority, publication, process attempts, activation, health and quiescent collection. The bootstrap has an explicit Windows service and installation path; protected installation and service acceptance remain open. Its default no-argument mode selects no modules.

The current [module planning contracts](module-planning.md) record exact installed dependencies for rollback retention. Catalog v2 metadata restricts executable packages to the supported machine host ABI; user-session activation remains unsupported. The optional [inventory host](native-inventory-host.md) supplies a fixed read operation over inherited pipes. Its source and package build do not establish protected service installation or endpoint acceptance.

## Feature installation lifecycle

1. Management settings produce a signed, versioned desired configuration for the device and selected users.
2. Resolve only enabled feature roots and the transitive closure of their exact dependency versions for that OS and architecture. Report incompatible versions, missing packages and cycles before downloading anything.
3. Fetch approved manifests and immutable packages through authenticated HTTPS. Validate signature, trust root, expiry, monotonic revision, platform, minimum bootstrap version, publisher and hash/size before activation. Never accept manifest-supplied shell commands or arbitrary installation paths.
4. Stage verified immutable packages and journal candidate-instance intent before launch. A restricted candidate may report readiness while it remains inert. Prove incompatible old instances quiescent, durably commit the active generation, and then authorize feature activation. Record last-healthy only after bounded operational health. Restore a retained healthy selection only when current authority still permits it. Keep desired, downloaded, installed, candidate, active, healthy, disabled and failed states separate.
5. Disabling a feature stops its event listeners, jobs and processes. Removing it releases dependency references. A shared dependency remains while another active module or rollback pin needs that exact version. Garbage collection happens only after quiescence and verified release of handles.

Installation, updates, pause, resume, disable, uninstall, repair, diagnostics and health are module lifecycle operations. A feature without meaningful pause semantics reports that explicitly. Rollback applies to code/configuration; it never pretends to undo an already completed external action. Offline devices keep their last approved healthy configuration, while expired or revoked authority prevents new work. Restoration never replays old mutations.

## Shared dependencies and isolation

The dependency graph uses exact versions and platform-specific immutable artifacts. One compatible copy can serve several modules. Incompatible ABI versions may coexist in isolated hosts; no global runtime upgrade may break an existing feature. Each module declares required privileges, capabilities, platform and session scope. A dependency cannot grant an undeclared permission to its parent.

The SYSTEM Windows host handles only approved machine functions. A separate user feature host handles clipboard, shell integration and user-session file access. The imported transient package-update broker retains its bounded role. macOS modules use launchd and appropriate user consent/entitlements. The Ubuntu wake relay uses its own limited module set. Server modules and console routes have their own feature registrations; disabling a client tile is not authorization enforcement.

Each feature owns its command/event schemas, implementation, settings, permissions, API routes, UI entry points, migrations and tests. Shared infrastructure exposes stable contracts. Database migrations are versioned and reversible where possible; disabling a module preserves data according to its retention policy. Features declare optional integrations, so Falcon, EMA and Cloudflare adapters can be independently configured or omitted.

## Initial module families

| Family | Optional feature modules | Shared dependencies |
| --- | --- | --- |
| Visibility | Inventory, health, lifecycle history | Device identity, observation store, audit |
| Recovery and access | Wake relay, RDP launcher/gateway, physical-session control | Site identity, connectivity negotiation, session authorization |
| Windows management | Windows Update, WinGet, Store, signed packages, indexing, policy groups | Privileged command host, scheduler, policy contracts, receipts |
| Integrations | Falcon, EMA, Cloudflare connectivity | Server secrets, provider clients, capability reporting |
| Sharing | File/folder transfer, clipboard sync, shell/share integration | Device trust, encrypted channels, resumable object transfer, user feature host |

The product excludes CRM, Android and AMAPI modules. Platform capability reports distinguish available modules from installed and active modules.

## Acceptance gates

Measure clean-install size, idle CPU/RAM/network and wakeups. Prove that disabled features leave no listeners or feature processes running and that their payloads are absent on a clean minimal install. Test dependency sharing, removal while still referenced, version conflicts, per-user/RDP isolation, hash/signature failure, revoked modules, interrupted download/activation, reboot, offline return and rollback. Verify that one failed module cannot remove device management or recovery access. No endpoint release is accepted as the thin agent until these checks pass.
