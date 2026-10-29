# Private writer watcher and finite ledger

`native/internal/processhost/internal/custody` contains a private admission component. It has no production constructor or caller. It does not create feature hosts, authenticate service peers, install services, or activate optional modules. The shipping bootstrap and current Manager are unchanged.

One registry owns service reservations. One vault runner serializes admission, dispatch, cancellation of queued entries, terminal completion and retirement for one writer incarnation. The state reducer performs memory decisions. Its runner observes the retained Windows process handle immediately before each command decision. A separate watcher waits on that same handle in finite 10 millisecond waits. A wait timeout only allows the watcher to check its own shutdown request. Only an actual process signal or an observation error triggers automatic sealing. Observation failure and process exit have distinct recorded causes.

The only current construction path is in same-package Windows tests. It creates the fixed harmless peer with CreateProcessW, retains the returned process handle continuously, checks exact object equality when reusing a writer, and starts one watcher and one runner. There is no PID lookup, trusted flag, production fixture option, restored custody or file-based proof. The source registry helper is a private memory reservation operation. It does not authenticate or mint writer identities.

## State and reservations

An admitted request stores its original identifier, fixed-size binding and request kind. Exact duplicates return the existing phase. A changed binding rejects. Start and Resume are ledger request kinds in this unit. Neither performs a Windows host operation.

The phases are queued, dispatched, returned, canceled and retired. Dispatch records the worker obligation before starting its worker. A separate completion courier joins that worker with a WaitGroup before publishing its reserved terminal event. The reducer releases the dispatched count only on that event. A caller deadline never removes the record. Sealing cancels queued entries under the same admission owner and requests cancellation of dispatched workers. Worker return cannot reopen the writer.

Every request reserves queue, terminal and lifetime tombstone capacity before admission. Dispatch exchanges a queue reservation for a dispatched reservation. Retirement releases terminal capacity and retains the request and binding as a replay tombstone. Writer records and their control allowances remain reserved for the registry lifetime. No timeout or session detach evicts them. There is no epoch rollover.

The test limits are finite configuration used by tests, not production sizing.

| Resource | Per writer | Service total |
| --- | --- | --- |
| Registered writer records and fences | One record per test-pinned incarnation | 4 |
| Attached sessions | 4 | 16 |
| Queued requests | 8 | 32 |
| Dispatched workers | 2 | 8 |
| Retained terminal records | 8 | 32 |
| Lifetime request tombstones | 16 | 64 |
| Ordinary request and response slots | 4 | 16 |
| Reserved control slots | 2 | 8 |

Control allowances are reserved when registering the writer. Controls have a separate bounded channel and response allowance. Seal requests coalesce through one signal and allocate no worker. Terminal events use a channel sized to the writer's maximum dispatched count. New admission cannot consume these paths. The registry lock contains only memory decisions. It never waits on a vault, worker, transport or Windows call.

`close` requests a monotonic seal and waits only for ledger drain. Its result explicitly names ledger drain. A deadline returns retained obligations. An empty ledger reports zero joined workers and supplies no process cleanup or host stop proof. Session reader and writer joins, owner shutdown, watcher shutdown, worker courier joins and original handle closure remain separate operations in the tests.

## Actual Windows verification

The fixed peer owns two independent inherited pipe sessions. Tests prove useful live requests and replies, exact duplicates, changed binding rejection, automatic sealing after exact process termination, denial of a parsed frame and an unread buffered frame from those two sessions, and a new test transport attached to the sealed old vault. That last transport is a same-user test construction and supplies no authenticated reconnect proof.

A held user-space worker remains dispatched across writer death, caller deadlines and repeated Close requests. A queued entry is known canceled by this ledger without dispatch. An oversized unread pipe reply remains unreturned while the second session and owner progress. The reply returns after exact peer termination, and the actual reader and writer workers join. Worker completion then reduces the outstanding count without reopening admission. This is not a hung CreateProcess test or a feature-host proof.

Separate tests exhaust per-writer and service queue, dispatch, terminal, tombstone, session and ordinary response budgets across two real writer processes. They retain control and retirement progress. Response and control saturation use a test-only paused runner, not a claimed stalled kernel operation. A fresh real writer completes useful work after old ledger bookkeeping while the old incarnation remains fenced. A retained deliberately broken explicit-seal-only owner admits its dead test writer until explicitly sealed. That negative control demonstrates why explicit seal injection alone is insufficient.

Only the memory ledger compiles on other platforms. The Windows watcher and all fixture construction are omitted there. No unsupported platform receives a success constructor.

## Remaining acceptance gates

This component supplies no original-root or whole-job stop proof, contained host creation, retained creation-abort custody, fallback transfer, protected namespace, service SID, selected-user token, privileged peer authentication, durable v2 resolution, collector integration, restart recovery, protected epoch anchor or thin-agent release wiring. Same-user pipes and process handles establish none of those properties. The paired privileged role trust consequence in the selected design is unchanged.

Production construction remains absent until those trust and continuity prerequisites are implemented and tested. Root integration still requires the ordinary repository checks, locked Windows restore, build and tests, PowerShell checks and exact-head platform CI. Protected storage and service boundaries need isolated elevated Windows CI. Real PostgreSQL is required for coordination changes. Actual Windows computers, selected-user sessions and the Ubuntu relay retain their separate acceptance pilots.
