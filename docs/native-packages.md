# Native package delivery

`native/internal/packages` stages verified inert files in a new uncommitted directory. It does not activate packages, run hosts, grant permissions, install services, or publish an installed receipt.

`Delivery.Stage` accepts an `Approval` derived by its caller from an authorized catalog, a signed publisher attestation, and the caller's trusted observation time. The separate generated `PackageAttestation` model binds the exact module ID, version, platform, publisher, layout, compressed archive SHA-256 and length, and every file's exact path, SHA-256, and inflated length. The existing version-1 planner manifest remains unchanged.

The installation owner supplies `authority.Trust` and `PublisherKeys`, which independently bind each approved publisher to its protected signing key identifiers. The envelope must verify under `publisher-attestation.v1`. Catalog approval cannot replace publisher verification. The attestation must be currently valid and agree with every package binding in the approval. This fixture publisher policy does not establish Authenticode, macOS designated requirements, notarization, production signer custody, or release acceptance.

## HTTPS boundary

`Open` constructs the HTTP client internally. It accepts no caller-supplied HTTP client or transport. It snapshots its origin list, publisher map, public keys, and optional CA pool. Origins contain only the exact HTTPS scheme and authority, with no path, query, credentials, or fragment. Each artifact URL passes the shared strict URL parser again before network access.

The transport uses normal certificate and hostname verification with TLS 1.2 or newer. It does not inherit environment proxies, use cookies, follow redirects, or request compression. DNS results must all pass the public address policy. The dialer connects directly to a checked IP while TLS verifies the approved hostname. Another DNS lookup cannot replace that destination during the request. Production rejects loopback, private, link-local, multicast, documentation, translation, and other reserved address ranges. The test package alone calls an unexported constructor that permits loopback with an explicitly supplied fixture CA. Production has no environment or configuration switch for that allowance.

Responses require status 200, exact `application/zip`, an exact Content-Length, no transfer encoding, and no content encoding. The request has a bounded context, response headers have a 16 KiB ceiling, and the reader stops after the signed length plus one byte. Length and whole-archive SHA-256 must match before ZIP inspection.

Defaults permit 16 MiB compressed, 16 MiB per file, 32 MiB inflated, and 128 entries. Configuration cannot exceed 64 MiB compressed, 64 MiB per file, 128 MiB inflated, or 512 entries. The timeout defaults to 30 seconds and cannot exceed one minute. Compression ratio cannot exceed 100 inflated bytes per compressed byte.

## Portable ZIP subset

The accepted ZIP format has a single disk, one central-directory record per regular file, version-needed and version-made-by values of 20, and methods STORE or raw DEFLATE. Flags, attributes, disk numbers, internal attributes, extras, comments, encryption, descriptors, and ZIP64 are unsupported and rejected. Directory entries are unsupported. Directories are inferred from file paths. Files must have positive lengths.

Local records begin at byte zero and appear in central-directory order. Each record begins exactly where the previous record ends. The central directory follows the final compressed file immediately. Its declared size ends exactly at the 22-byte end record. Prefixes, gaps, overlapping ranges, and trailing data are rejected. Local and central versions, flags, method, timestamps, CRC, sizes, and names must agree exactly. DEFLATE must consume exactly its compressed range. Inflation reads at most the declared file length plus one byte. Actual CRC, inflated length, total size, and SHA-256 must match.

Paths contain only ASCII letters, digits, dots, underscores, hyphens, and slash separators. Paths are at most 240 bytes with at most eight components. Empty, dot, dot-dot, absolute, drive, UNC, backslash, colon, control, Unicode, reserved Windows device, and trailing-dot or trailing-space names are rejected. File and directory prefix spelling must be consistent under ASCII case folding. Duplicate files and file-directory conflicts are rejected. This ASCII subset removes Unicode normalization ambiguity. The signed inventory must match the archive exactly.

`passive-v1` permits only `data/` files. `native-host-v1` requires `bin/host.exe` on Windows or `bin/host` on macOS and Linux. Other files must be under `data/`. These fixed names identify a layout and do not authorize execution. Every staged file has mode 0600, including host bytes.

## Staging boundary

The caller supplies an already controlled staging parent. `Open` retains its `os.Root` directory handle. Each operation exclusively creates a random `uncommitted-` directory with mode 0700. Each inferred directory is created exclusively, opened through its parent handle, and checked against the created directory identity. Files are created through retained directory handles with create-exclusive semantics. No existing file is replaced. Actual bytes are read back through the same file handle with a bounded reader, then compared with the verified content. The path must still reference that file when checked.

A successful opaque `Receipt` identifies verified staging only. Its zero value carries no stage. A write, cancellation, or verification failure returns no receipt. A failure after directory creation can leave an `uncommitted-` directory, identified in the error. The generation owner must treat all such directories as uncommitted and clean them only under its own custody rules. Concurrent attempts use distinct directories and cannot overwrite each other.

This ordinary-user unit does not establish Windows private ACLs, a privileged root owner, protection against another process with the same account's filesystem rights, power-loss durability, generation-pointer publication, process containment, or quiescent collection. Those remain separate platform and lifecycle acceptance gates.

## Verification

Run from the workspace root with Node 24 and Go available:

```powershell
pnpm --filter @one-control/modules build
node packages/module-contracts/scripts/generate.mjs --check
node --test packages/module-contracts/tests/*.test.mjs
go -C native vet ./...
go -C native test ./...
```

Tests generate fresh RSA3072 fixture keys in memory, use real loopback TLS, sign exact attestation bytes, and inspect actual staged files. They cover passive and fixed host layouts, cross-language wire parsing, publisher and package binding failures, transport failures, malformed ZIPs, every truncation of a valid archive, inflation ceilings, concurrent staging, and a partial write sequence that cannot overwrite the first file or return a receipt. No downloaded code runs.
