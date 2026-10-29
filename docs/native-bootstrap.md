# Native bootstrap foundation

The `native/` Go module contains the provider-free bootstrap. With no arguments, `oc-bootstrap` resolves a built-in empty selection and prints its plan as `empty-selection-foundation`. Explicit configuration enables the Windows service, protected enrollment and credential rotation, authenticated configuration retrieval, package delivery, lifecycle supervision and inventory command dispatch. Optional engines are separate module packages. Production trust and target-specific acceptance remain required.

`scripts/install-native-agent.ps1` provisions the bootstrap only after checking its hash and Authenticode publisher. It accepts an explicit trust configuration and protected invitation file. Enrollment and rotation persist intent before sending requests; uncertain outcomes are reconciled without replaying issuance. The installer and protected storage implementation have not yet passed an elevated endpoint pilot. The macOS service and protected storage adapters remain unfinished.

`native/internal/selection` ports the current pure TypeScript planner. It validates every installed receipt and edge before returning any removal candidates. Historical rollback pins retain their complete installed dependency closure without activating a disabled root. Exact versions coexist, shared packages deduplicate by exact identity, dependency ordering is deterministic, and installed receipt hashes only decide whether a download is required. A receipt match does not verify installed bytes.

The conformance exporter runs the unchanged 30 TypeScript tests through an import hook. It captures their 32 planner invocations, then adds deterministic seeded graphs and boundary inputs. `packages/modules/fixtures/planner.json` contains 394 serialized inputs and oracle outcomes. Go executes that same corpus and compares complete plans or stable error codes and module identities. This is differential evidence for those inputs, not a proof for every possible JSON value.

## Shared wire contract

`packages/module-contracts/schema/wire.json` owns the wire types, allowed domains and platforms, number and identity patterns, and error registry. `scripts/generate.mjs` generates Go structs and the embedded schema, plus TypeScript interfaces and the schema constant. Both runtime parsers interpret that schema. Regeneration fails on drift. The existing planner's version-1 manifest shape remains unchanged. Its artifact URL acceptance is intentionally tightened by the common rule below. This unit does not invent package execution or host ABI authority.

Parsing rejects malformed UTF-8, unpaired Unicode surrogate escapes, duplicate keys, unknown fields, missing fields, `null` in place of a required value, noncanonical numeric spellings, and integer overflow. Wire epoch, revision and root version values are decimal strings bounded to uint64. Timestamps are canonical positive Unix-second integers within JavaScript's exact integer range. Package size remains an integer from 1 through 2,147,483,648. Module versions retain three components with at most five digits each and no leading zeros.

Artifact URLs use an explicit absolute HTTPS grammar shared by the TypeScript reference schema, Node wire parser and Go wire parser. The scheme is case insensitive and must be followed by `://`. A host is required. DNS names use ASCII letters, digits and hyphens, labels of 1 through 63 characters without leading or trailing hyphens, and at most 253 characters excluding an optional final dot. International names must use ASCII DNS labels. Numeric or hexadecimal final labels require canonical four-component decimal IPv4 with no leading zeros or final dot. Bracketed IPv6 is validated as an address, including embedded canonical IPv4, without zones or IPvFuture. An optional port has 1 through 5 decimal digits and a value from 0 through 65,535. Path and query use RFC 3986 ASCII characters and complete percent escapes; Unicode path and query bytes must be percent encoded. A path begins with `/`, and a query may contain `/` and `?`. All credentials, including empty userinfo, fragments including an empty `#`, backslashes, literal whitespace and control characters are rejected. The validators preserve accepted URL bytes rather than normalizing them.

This is a deliberate pre-consumer metadata contract change. Previously JavaScript repaired `https:example.com/package` and backslash spellings that Go rejected, while Go admitted malformed authority and port spellings. The shared grammar rejects those ambiguous inputs in every validator. It does not authorize an origin, resolve DNS, restrict address ranges, decode international labels, validate query capabilities or authorize redirects. Delivery must separately authorize origins and resolved destinations before network access. The 88 URL boundary cases are checked against explicit expectations in both runtimes and exported through the TypeScript oracle into the differential planner corpus.

The envelope has exactly `protected`, `payload`, and `signature`. Each value is canonical unpadded base64url. Protected bytes contain `schemaVersion:1`, `domain`, `alg:"PS256"`, `rootVersion`, and `keyId`. The signature covers the following bytes, without parsing and reserializing them:

```text
ASCII("ONECONTROL-SIGNED-V1\n")
u32be(keyIdUTF8.length) || keyIdUTF8
u32be(protectedBytes.length) || protectedBytes
u32be(payloadBytes.length) || payloadBytes
```

RSA keys contain 3,072 through 8,192 bits and exponent 65,537. PSS uses SHA-256 and exactly 32 salt bytes. Trust rejects repeated key identifiers or reused public-key material. Each key authorizes one exact role and has an explicit validity interval. Catalog, policy, freshness, root, publisher attestation and bootstrap release are separate protected domains. An installation owner supplies trusted public keys and the current root and authority epoch. This unit does not implement threshold root rotation, trust enrollment or production key custody. Test private keys exist only in process memory.

An immutable `Policy` binds device ID, enrollment instance, platform and scope. Machine scope binds `machineId`. User scope additionally requires `principal`, `sessionId`, `sessionIncarnation`, and `localNonce`. No other session fields are accepted for machine scope. These values must match the local binding exactly.

The separate `Freshness` response binds the immutable policy's exact SHA-256, device, enrollment instance, authority epoch and a locally generated 32-byte request challenge. Its maximum validity interval is 300 seconds. The native `Challenge` object belongs to a single serialized request owner and is consumed after acceptance, including if checkpoint persistence subsequently fails. Every restart creates a fresh challenge. A new freshness response can authorize the same unchanged policy revision without changing that policy's identity.

Within an authority epoch, lower revisions fail and an equal revision requires exactly the same policy bytes. A larger authority epoch requires a larger installed trusted root version. The policy cannot authorize its own epoch transition. Time cannot move below the accepted checkpoint's observation time. Whole-disk rollback resistance is not provided by local files; a restored endpoint requires a new live authenticated challenge before future activation work.

`authority.Accept` performs no I/O and consumes its request challenge. Its caller must commit the returned checkpoint before forward effects. `authority.Store` implements a sequential, checksummed, flushed append log with compare-and-swap against the previous checkpoint. Corruption or a torn frame fails closed. The [ownership adapter](native-ownership.md) now replaces the original O_EXCL sentinel with a persistent kernel lock. Its file survives writer death while OS ownership releases. Protected installation storage and durable generation recovery remain required before full crash/restart lifecycle acceptance. The log is not a claim of power-loss-safe filesystem transactions, protected Windows storage or hardware rollback resistance.

## Run the checks

Run these commands from the workspace root with Node 24 and the Go toolchain on PATH:

```powershell
pnpm --filter @one-control/modules build
node packages/module-contracts/scripts/generate.mjs --check
node packages/modules/scripts/export-fixtures.mjs --check
node --test packages/module-contracts/tests/*.test.mjs
go -C native vet ./...
go -C native test ./...
go -C native run ./cmd/oc-bootstrap
```

The authority tests generate fresh RSA3072 keys in memory, verify Node signatures in Go and Go signatures in Node, reject altered byte framing and wrong salt lengths, and exercise policy and user-session binding failures. Node is a development dependency of these interoperability tests. The compiled executable has no Node or .NET dependency.

For a stripped Windows artifact with no console allocation, build with `go -C native build -trimpath -ldflags '-s -w -H=windowsgui' -o <absolute-output.exe> ./cmd/oc-bootstrap`. Other operating systems omit `-H=windowsgui`. The executable still writes JSON to redirected stdout. `native/scripts/measure-empty.ps1` runs the actual Windows artifact in a new empty directory and records three live OS process, TCP and UDP snapshots during a 20-second idle run. It asserts zero child processes, network endpoints and working directory entries. These bounded snapshots do not establish the later 30-minute idle budget or exclude every transient lifetime event.

## Remaining acceptance units

The next units must add real loopback HTTPS delivery, publisher-attested packages, bounded ZIP validation, protected staging and separate durable candidate/active/healthy generations. The ownership adapter supplies kernel locking and a Windows suspended-create/Job Object host boundary, with its own verification limits. An absent active pointer must never imply there is no candidate child.

No package executes in this foundation, so it does not claim lifecycle, inventory, service, recovery, mutation replay or real endpoint acceptance. Root custody, signing, protected storage, native Windows/macOS/Linux execution, elevated Windows storage CI and physical endpoint pilots remain explicit gates. Original archives, excluded products and inherited providers remain outside the executable.
