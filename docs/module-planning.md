# Module planning contracts

`packages/modules` computes a plan without downloading, starting or deleting packages. `resolveModulePlan` takes a verified catalog, enabled feature versions, disabled module IDs, a device platform, the bootstrap version, granted permissions and installed receipts.

The caller verifies catalog signatures, expiry, revision and authorization before planning. The planner validates metadata and graph consistency. It cannot authenticate persisted receipts or prove installed bytes by reading a hash field. The future endpoint state owner must protect those facts.

## Desired packages

Enabled feature roots select exact versions. The planner resolves their transitive dependencies in dependency-first order. A shared exact version appears once and lists the feature roots that need it. Different versions remain distinct packages. Missing manifests, cycles, unsupported platforms, old bootstrap versions and ungranted permissions reject the entire plan.

`packages` describes the desired closure and reports whether each package needs a download. `deactivate` lists currently active installed packages absent from that desired closure. `removalCandidates` lists installed packages outside both desired and rollback-retained closures. A future executor must establish quiescence before deleting candidates.

## Installed receipts and rollback

Each installed receipt contains its ID, exact version, observed SHA-256 and size, active state, optional rollback pin and required exact direct dependencies. Leaf packages explicitly record an empty dependency map. Installed state describes complete committed installations, not partially staged downloads.

Rollback retention follows installed receipt edges. It does not consult the current catalog, which may omit historical versions. A pin retains the root and its complete transitive closure. Retention never enables a feature or requests a download. Disabling every feature can therefore deactivate old packages while retaining their bytes for rollback.

The planner validates the whole installed graph before returning any plan. Missing receipts, duplicate identities, invalid fields and cycles reject the snapshot, including disconnected unpinned components. Limits are 512 installed receipts and 32 dependencies per package. A planning failure must not be interpreted as permission to collect everything.

## Design choice and verification

The review compared installed dependency receipts with complete rollback generations. Receipts keep historical dependency facts beside the installed package and preserve one planner operation. Generations would add capture, release and reconciliation state before an activation owner exists. A later generation design can replace the pin model when that owner exists.

Two independent same-model candidates and a separate judge agreed on installed receipts. The correction uses a private strict schema and graph traversal. A regression first reproduced deletion of a pinned feature's dependencies. The corrected 30-test suite covers complete retention, shared references, last-pin release, catalog absence, disabled activation, malformed receipts, missing edges, cycles and input preservation.
