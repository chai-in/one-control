# Server module authority implementation

This is unreleased implementation. Scope administration, native enrollment, signed catalog/policy/freshness publication and native observation ingestion are connected in the active source. The Windows installation owner and feature providers are not yet connected to the native transport. No production keys, scopes, enrollments or deployments are created at startup.

## Persistence and restoration

Ordered migrations preserve frozen v1 statements and use transaction advisory lock 748391234 at READ COMMITTED. Metadata records each later migration ID and checksum; unknown versions, gaps and mismatches prevent readiness. Current history extends through v9:

| Version | Added state |
| --- | --- |
| 2 | Custody, scopes, grants, native invitations/enrollments and server module states. |
| 3 | Desktop policies/history, groups/assignments/defaults and canaries. |
| 4 | Company people, assets and explicit source links. |
| 5 | Falcon sync state, cached observations and event receipts. |
| 6 | Native custody/evidence, publication intents/heads, selections and nonce receipts. |
| 7 | Native report sequence streams and received observations. |
| 8 | Native job admissions, claims and terminal receipts. |
| 9 | Encrypted recovery keys and a separate reveal grant. |

PGlite backup manifests have explicit inventories for every supported version. Isolated restore revokes credentials/enrollments/grants, consumes invitations, terminalizes old jobs, disables modules, aborts canaries, pauses running sync, clears publication heads and quarantines publications/nonce receipts. Exact signed bytes and observations remain historical evidence. Ordinary routes cannot clear quarantine. Real PostgreSQL dump/restore and current populated-fixture acceptance remain open.

## Scope and enrollment

ModuleControl owns runtime, scope, device, enrollment and exact credential locking in that order. Scope fences serialize grants, module enablement and publication admission. Management identity is verified issuer plus subject; global operator status does not confer ownership of existing scopes. Scope creation is explicit. Grants, ceilings and module selection use decimal-string version CAS.

| Route | Purpose |
| --- | --- |
| POST /v1/scopes | Explicit personal/company scope and owner. |
| GET /v1/scopes/:id/modules | Registry, ceiling and selected server modules. |
| PUT /v1/scopes/:id/grants | Owner changes an issuer/subject permission. |
| GET /v1/scopes/:id/grants | Owner inspects active and revoked grants. |
| PUT /v1/scopes/:id/permissions | Owner changes the permission ceiling. |
| PUT /v1/scopes/:id/server-modules | Configure grant selects roots and shared dependencies. |
| POST /v1/scopes/:id/native-invitations | Binds an invitation to device, platform and machine. |
| POST /v1/agent/native-enroll | Redeems an invitation and client-generated credential hash; existing devices require live proof. |
| GET /v1/agent/native-enrollment | Retrieves the immutable installation binding. |
| POST /v1/agent/native-credentials/rotate | Rotates within enrollment with bounded overlap. |
| POST /v1/scopes/:id/native-enrollments/:enrollmentId/revoke | Revokes the enrollment and credential lineage. |

Native credentials cannot enter legacy agent routes. Legacy fleet mutation routes reject native devices. Enrollment is an administrator-controlled ceremony, not hardware attestation. No identity is inferred from hostname, email, Falcon data or asset links.

## Signing and publication

NATIVE_AUTHORITY_CONFIG explicitly names a local custody document with custody reference, nonzero root version/epoch, role-specific public keys, signer key-file references, publisher-key bindings, artifact origins and exact issuer/subject custody administrators. Private signing keys load only from the canonical private credential store. Distinct RSA keys serve catalog, policy and freshness roles; publisher keys are verification inputs only. No root or publisher private key is loaded or generated.

POST /v1/authority/native-custody/activate requires operator authentication and configured custody-administrator membership. It records public trust and activates only an unconfigured runtime. It cannot reactivate restored authority or rotate roots. Recovery/root rotation remain separate work.

The optional native-distribution module requires native.distribute:

| Route | Purpose |
| --- | --- |
| GET /v1/scopes/:id/native-modules | Published catalog and platform selections. |
| POST /v1/scopes/:id/native-modules/catalog | Publish entries and exact publisher attestations using request UUID and expected version. |
| PUT /v1/scopes/:id/native-modules/selection | Select exact modules, disabled modules, permissions and bootstrap version per platform. |
| POST /v1/agent/native-configuration | Exchange a locally generated nonce and native bearer for signed configuration. |

Catalog admission validates publisher signatures, artifact bindings, package inventory/layout, origins and dependencies. Exact payload/protected bytes, revision, authorization version, predecessor and deadline freeze in an intent. Catalog/policy signing runs outside database locks; finalization rechecks custody, authority version and head before commit. Signer responses are verified locally. Accepted retries return first-committed bytes.

Policy derives its device/platform/machine binding from enrollment and selection from platform settings. The original selector's grant remains live. Native wire schemas remain unchanged; desktop enforcement settings are not carried in module-selection policy yet.

Freshness signs the exact policy digest and locally owned nonce with a maximum 60-second life. Its bounded signer call uses the common locks. Exact reply bytes and receipt commit before delivery. Expired response bodies are cleared while nonce tombstones remain; an enrollment permits 64 live receipts and 250,000 lifetime challenges before explicit reenrollment. These are implementation limits, not measured capacity claims.

The console imports a JSON catalog bundle containing entries and base64url attestations, then edits platform selection. Unacknowledged publication retains its request UUID, scope, expected version and exact input for an explicit retry; clearing the local draft does not cancel a server intent. Shared dependencies can be blocked explicitly. Catalog replacement requires explicitly saving a selection against the new head. Permissions must fit the scope ceiling. Publication alone never downloads or activates a feature.

The Management scopes panel creates explicit personal/company scopes, edits owner permission ceilings and configured server roots, and lists/restores/revokes issuer-and-subject grants. Scope reads include the caller's current grants so the console can expose applicable controls; the server independently enforces each mutation. The final owner cannot be revoked. Module dependencies remain distinct from explicitly selected roots.

## Native transport and observations

The native/internal/controlplane client uses a fixed HTTPS origin without redirects and owns each challenge through the existing lifecycle manager. Authority verification and journal commit precede download/activation. Installation trust and credentials come from the installation owner. The transport never loads trust from its response and does not import inventory collection code.

The optional native-observations module owns POST /v1/agent/native-report, GET /v1/agent/native-report-state and GET /v1/scopes/:id/native-observations. Reports require current published policy and live enrollment. Inventory also requires the selected inventory module/version, permission and server inventory admission. Heartbeat updates liveness; inventory stays in its own labelled observation store.

One decimal sequence stream per enrollment admits the next report or acknowledges an identical last retry. Conflicting bytes and gaps are refused. The native outbox flushes prepared bytes before sending, retains pending outcomes, reconciles lost acknowledgments against server receipts and refuses silent counter resets after restore. Its journal requires an installation-owned protected directory; checksums detect corruption, not malicious edits. Pending unsent reports tied to replaced policy require reconciliation rather than silent rewriting.

The inventory console shows collection/receipt times, enrollment, architecture, Windows version, CPU and memory with unavailable/unsupported values. These are authenticated self-reports, not hardware attestation.

The separate `oc-inventory` executable serves a bounded `inventory.scan` operation only after activation. The lifecycle owner checks current policy, permission, package and healthy generation under its lock and binds results to the collection-time policy digest. The transport submits those results through the existing durable outbox. See [native inventory host](native-inventory-host.md). No inventory collector is linked into the bootstrap or transport library.

## Remaining execution and acceptance

Native client command execution, signed desktop settings, protected service/session custody, remaining feature hosts, full inventory and endpoint acceptance remain open. Native server claim, renewal and terminal receipts are implemented separately from legacy dispatch. Claims recheck live creator/approver grants, module selection and policy; client-generated lease secrets stay out of the claim response/database. Late evidence is retained for reconciliation and restored claims are quarantined. Protected client execution remains unfinished, so this intermediate workspace must not be deployed as a complete command service.

Falcon/EMA reads have scoped admission. Falcon sync and webhooks now use the runtime/scope fence; credentials remain bound to configured scope. Disabling modules does not replay queued or restored work.

Added TypeScript paths and the Go transport library compile. Behavioral tests were deferred under current instructions. Earlier PostgreSQL results predate these migrations. Actual HTTP-to-Go verification, populated PostgreSQL transactions/restore, race coverage, full pnpm checks, locked Windows tests/build, PowerShell checks and protected Windows CI remain mandatory before commit or accepted release.
