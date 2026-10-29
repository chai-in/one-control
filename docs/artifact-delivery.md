# Private artifact delivery

The imported `apps/artifacts` component provides download-only delivery of signed agent MSI payloads through a dedicated Cloudflare Worker and private R2 bucket. Phase 1 validates its request policy locally. Cloud resources and release trust have not been configured for One Control. Module distribution will reuse verified transport and signing primitives through the module architecture, rather than treating every feature as an agent replacement.

GET and HEAD requests require an HMAC capability bound to the exact host, content-addressed path, complete byte size and expiry. Capabilities last at most 24 hours. Responses are uncached; partial responses, invalid requests and storage failures fail closed. The download key cannot enroll devices, approve operations or sign release metadata. Agent checks for signed metadata, increasing sequence, hash, length, allowed origin, Authenticode publisher and recovery health remain mandatory.

## Configure a new deployment

Copy `apps/artifacts/wrangler.example.jsonc` to the ignored `wrangler.jsonc`, then explicitly select the personal Cloudflare account, dedicated Worker, private bucket and public HTTPS host. The example contains placeholders and no inherited account identifier. Review existing resources before using a name. Keep bucket public access disabled.

Build with `pnpm --filter @one-control/artifacts build`. Initialize protected download-key storage using `scripts/initialize-artifact-store.ps1` from elevated PowerShell. The default root is `C:\ProgramData\OneControl\Artifacts`; repeated initialization preserves the key. Invalid or partial state must be preserved for diagnosis. This storage is separate from release signing and device credentials.

The secret configuration script requires `-WranglerScript`, `-ConfigurationFile`, `-ExpectedAccountId`, `-ExpectedWorkerName`, `-ExpectedBucketName` and `-ExpectedPublicHost`. Target mismatches fail before supplying the key. The download-only secret passes over stdin. These are deployment instructions; phase 1 does not execute them.

## Stage immutable signed payloads

After validating the final MSI signature and timestamp, compute its SHA-256 and stage it under `artifacts/<sha256>/one-control-agent-<version>.msi`. Never replace an existing object. Read newly staged bytes back and verify size and hash before registering a release. `scripts/issue-artifact-url.ps1` requires an explicit `-Origin` together with the signed MSI and publisher pin.

The wrapper checks the MSI while holding a read-only handle and writes bearer authorization to protected storage. It prints metadata, not the bearer URL or key. Authorization must cover the approved maintenance window. Reissue an expired release with a new sequence; never replay uncertain installation work.

## Acceptance

Local tests cover HMAC verification, request mutation, expiry, host/path binding, GET/HEAD behavior and length mismatch. Windows administrator tests additionally cover private ACLs, DPAPI, unsigned MSI refusal and preservation of partial state. Deployment acceptance still needs real public TLS, private R2 access, streaming and an independent full download hash. See current phase 1 results.
