# Native module generation lifecycle

`native/internal/lifecycle` joins signed selection, publisher-attested HTTPS packages, an append journal, and owned Windows fixture hosts. It is a library pilot. The shipping `oc-bootstrap` command still runs its empty-selection foundation and does not enroll a device or call this manager.

Normal Windows reconciliation downloads only the selected exact dependency closure, publishes verified bytes, separates candidate, active, and healthy generations, and stops disabled hosts before collection. A restored nonterminal host attempt becomes `unknown`. It blocks further activation and collection until independent custody can be proved. Automatic recovery after a controller crash remains incomplete.

## Authority and installed records

The normative wire schema is `packages/module-contracts/schema/wire.json`. Generated Go and TypeScript records use the same strict parsers. Manifest version 1 and planner semantics remain unchanged.

| Record | Meaning |
| --- | --- |
| `ModuleCatalog` | A separately signed `module-catalog.v2` payload with an authority epoch, immutable revision, validity interval, and catalog entries. |
| `CatalogEntry` | A version-1 manifest plus metadata for each artifact platform. Metadata binds publisher, layout, host ABI, machine scope, and the exact publisher-envelope digest. |
| `CatalogFloor` | Accepted root version, catalog authority epoch, revision, and exact catalog-payload digest. It advances independently of the policy revision. |
| `PublishedPackage` | Immutable catalog metadata, platform, exact publisher envelope, derived package identity, verification time, and publication state. `intent` grants no execution authority. |
| `Generation` | An identity derived from ordered exact package identities and the explicitly enabled feature roots. Shared packages remain passive. |
| `HostAttempt` | A random instance nonce bound to one generation and feature package. Its state is `intent`, `stopped`, or `unknown`. |
| `LifecycleState` | Authority checkpoints and envelopes, installed records, host attempts, candidate, active, healthy, and trash records. One manager owns this state. |

`authority.AcceptSelection` verifies the catalog signature, metadata, dependencies, validity, epoch, and independent floor. Duplicate entries, missing or cyclic shared dependencies, incomplete platform metadata, and incompatible layout or ABI combinations fail before network access. The policy must bind the exact catalog payload digest. A newer policy cannot lower the catalog revision or replace an equal revision with different bytes. An epoch increase requires a larger trusted root version.

`Manager.Reconcile` verifies the immutable policy and separately signed fresh challenge response through the existing authority boundary. It copies selected publisher envelopes and verifies their exact catalog digest and publisher signature before committing authority. The caller supplies trusted observation time. Public keys are copied when the manager opens. Caller mutation after validation cannot change the accepted selection.

The journal retains exact signed policy, freshness, and catalog envelopes. A restart validates their signatures and their relation to the checkpoints. It checks device, enrollment, platform, and full scope against the signed policy, and derives root and epoch expectations from installed trust. A rewritten checksum or unsigned binding digest cannot substitute foreign signed authority. It does not turn restored files into fresh execution authority. A new signed request and local challenge are required for reconciliation.

The current `Options.Trust` contains only one root version. Although the floor rules permit root-authorized epoch transitions, reopening history under a replacement root requires a trusted historical-root verification contract that this pilot does not provide. A mismatched historical root fails closed. Threshold root updates, historical key custody, enrollment, and revocation remain separate work.

## Publication and generations

`Open` requires an absolute controlled root shared with the delivery owner. A stable kernel lock serializes feature-state writers. It does not prove that a previous writer's children have exited. The recovery service never writes the feature journal.

The journal uses a big-endian length, exact JSON bytes, and SHA-256 for each append frame. Each append validates schema, immutable installed records, dependency closure, generation pointers, host membership, sequence, monotonic authority, and permitted state transitions before writing. The file is flushed before the manager changes its in-memory state. A failed write poisons that manager. Torn frames, checksummed invalid pointers, and inconsistent history fail closed on reopen. The current limits are 6 MiB per frame and 64 MiB per log. There is no compaction protocol in this pilot.

Reconciliation follows this order.

1. Commit accepted policy and catalog authority before package or process effects.
2. Journal package intent. Download actual HTTPS ZIP bytes through `Delivery.Stage`, then verify and rename the inert directory to `package-<identity>`. Commit publication only after revalidation.
3. Journal the exact candidate generation. Stop prior hosts and require the process adapter's quiescence proof.
4. Journal each new instance intent before process creation. Resolve only the fixed `bin/host.exe` path after verifying installed inventory and its publisher attestation again.
5. Await bounded Ready responses. Candidate hosts remain inert.
6. Commit active before sending Activate. Publish healthy only after matching bounded operational health responses.

The Windows launch uses `PROC_THREAD_ATTRIBUTE_JOB_LIST` during suspended creation, an explicit inherited pipe-handle list, checked job membership, and checked resume. A failed creation attribute never falls back to late job assignment. The unnamed job rejects breakaway and uses kill-on-last-close. The process adapter retains exact process, thread, job, and pipe handles while the controller lives.

The manager rejects a Windows binding for the wrong runtime architecture before authority or network effects. On macOS and Linux, `Reconcile` returns `processhost.ErrUnsupported` before those effects. Native Unix execution needs its own proved containment adapter. Cross-compilation does not provide that evidence.

An unchanged healthy selection checks health without fetching packages or replacing host instances. A newer valid policy can select a retained prior generation only when the current signed catalog still authorizes its exact closure. It cannot restore an old policy or lower either authority floor.

`Collect` retains every package referenced by candidate, active, or healthy pointers and every nonterminal host attempt. It validates installed inventories before deleting unused bytes. A trash intent precedes rename and removal. Interrupted trash operations resume byte removal only. The manager retains immutable package and dependency records after byte removal so a later selection requires verified download and publication again.

Each package's immutable `verifiedAt` equals its insertion checkpoint time. Replay verifies the publisher envelope at that accepted time. Quiescent collection uses that authenticated historical context, so expiry does not make unused bytes permanent. Current-time checks remain required for staging, installed reuse, and launch. An expired pinned package remains retained and cannot gain current execution authority through collection.

A never-published intent can be marked for collection without an installed directory. An intent whose rename completed before its publication receipt must pass complete installed-inventory verification before collection. An interrupted stage can still leave an inert `uncommitted-` directory. This pilot does not reclaim every abandoned stage. An uncommitted directory never grants execution authority.

## Controller death and custody

On reopen, any journaled `intent` host attempt becomes `unknown`, including an attempt whose process creation might never have happened. The manager cannot infer quiescence from a released writer lock, a missing PID, an absent named job, or a grace delay. Unknown custody blocks collection and conflicting activation. It can still commit a newer valid authority floor before reporting `ErrUnknown`.

The separate Windows custody experiment found that a missing job name could coexist with an unsignaled retained process handle after controller death. Holding a separate recovery job handle also prevented last-close termination until explicit termination. The manager therefore has no missing-name or delay fallback.

Independent custody must retain or otherwise prove the exact containment boundary across controller death without letting a second component write feature state. That handshake, service supervision, handle transfer, collision checks, and its own failure matrix remain required before automatic crash recovery can pass.

This pilot has no external mutating-job dispatcher. It does not port the C# operation engine, restore its receipts, or replay uncertain commands. Provider operations and their no-replay acceptance remain later units.

## Verification and release limits

Run the native gate from the workspace root with Node 24 and the local Go toolchain.

```powershell
pnpm test:native
```

The gate checks generated contract drift, Node and Go contract behavior, the existing planner corpus, Go vet and tests, production file selection, and the actual stripped empty bootstrap. Its separate tagged step runs the integrated fixture tests.

```powershell
go -C native test -tags=onecontrol_lifecycle_fixture ./internal/lifecycle -count=1 -v
```

Only that build tag exposes the loopback fixture constructor. Normal package builds exclude `fixture_lifecycle.go`. Production has no environment switch for private-address access or disabled TLS validation. The optional `ONE_CONTROL_LIFECYCLE_EVIDENCE` environment variable belongs only to tagged test files. It saves actual public fixture artifacts and signed requests under an absolute test output directory. Private test keys stay in process memory or temporary controller input deleted by test cleanup.

On Windows, the integrated test compiles a fresh harmless fixed host, serves actual ZIP bytes over loopback TLS, verifies fresh PS256 catalog, policy, freshness, and publisher envelopes, and inspects actual installed files and child processes. It exercises empty selection, one feature, two features with one shared exact dependency, unchanged selection, disable one, disable all, retained selection under newer authority, collection, download after collection, and a graceful restart. Rejected old policy, equivocation, and newer policy with an older catalog leave journal, network count, and host ownership unchanged.

The controller-death test interrupts actual subprocesses at 14 boundaries. Five pre-instance interruptions recover through a fresh selected request. The rename interruption recovers by disabling and collecting the interrupted publication. Instance intent and five launched-host boundaries recover as unknown and reject activation and collection. The test observer retains actual live host process handles and waits for exit after controller termination. Two trash interruptions resume removal. These are bounded fixture observations, not a proof that the restarted manager recovered custody.

Portable journal tests reject every nonempty first-frame truncation, a checksummed invalid pointer, validly signed foreign binding, and altered unsigned root metadata. Installed tampering and caller mutation have separate assertions. Collection regressions cover an actual missing TLS archive, expired unused bytes after a graceful restart, repeated collection, and expired pinned bytes that still fail current-time reuse and launch.

This unit does not establish protected Windows ACLs, a privileged installation root, executable verification against hostile same-account writes, power-loss directory durability, hardware rollback resistance, production signers, Authenticode, notarization, native Unix containment, service installation, user-session hosts, or physical endpoint acceptance. The fixed fixture protocol has no provider data channel or shared-library loading contract. The empty bootstrap has no production lifecycle client. These are release and product requirements, not completed capabilities.
