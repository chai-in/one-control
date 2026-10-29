# Optional native inventory host

`modules/inventory/native/cmd/oc-inventory` is a separate executable for the optional `inventory` module. It uses the existing fixed Windows inventory collector. The bootstrap and control-plane transport do not import that collector. Its fixed operation is `inventory.scan`, requiring `inventory.read` in the active policy and package manifest. It does not implement application inventory, update execution, scripts or shell access.

## Host lifecycle and IPC

The executable accepts only the launch arguments `--one-control-host-v1 <instance>`. It sends readiness over its inherited output pipe without collecting anything. Activation enables request handling; health and stop use the existing control messages. EOF exits the process. The module receives no control-plane URL, enrollment credential or signing key.

Host messages retain version 1, instance and monotonically increasing sequence. Existing control frames are byte-compatible. Feature requests add the optional `payload` field, containing canonical unpadded base64url bytes, with types `request:<operation>` and `result:<operation>`. The frame limit is 16 KiB and decoded payload limit is 8 KiB; inventory JSON retains its existing 4 KiB limit. Legacy control-only hosts are not assumed to implement feature requests.

The host accepts only an empty input for `inventory.scan`. A handler failure, invalid request or pipe failure terminates the host. Parent-side cancellation, timeout or invalid response uses the existing forced-stop and containment accounting; it does not retry an operation. Readiness does not authorize collection.

`lifecycle.Manager.Invoke` requires a healthy active generation, current signed policy, selected feature/version and declared/granted permission. It holds the lifecycle owner during the request, limits execution to policy expiry and a 25-second operation budget, and returns the policy digest with the result. Failed requests record stop/unknown custody through the existing generation owner. Protected user-session execution remains separate work.

`controlplane.Client.CollectInventory` calls the fixed inventory operation and checks the collection-time policy digest before preparing its durable report. A selection change cannot silently relabel an observation with new policy authority. The existing report outbox retains uncertain deliveries and reconciles exact receipts. It does not collect on startup or schedule scans; the installation/service owner must explicitly call it when this module is enabled.

## Building a candidate

`scripts/package-native-feature.mjs` builds a single selected feature for `win-x64` or `win-arm64`, without CGO, into a new output directory. It produces the fixed `bin/host.exe` ZIP layout, exact file/archive hashes, a planner manifest and unsigned publisher-attestation request. It does not load keys, sign, upload, publish, install or execute the host. Supply new release configuration explicitly:

```powershell
node scripts/package-native-feature.mjs --feature inventory --version 0.1.0 --platform win-x64 --output .local/inventory-candidate --artifact-origin https://artifacts.example.invalid --publisher one-control --issued-at 1793318400 --expires-at 1793404800
```

The example URL is deliberately non-deployable; timestamps and publisher are examples. A real publication needs a configured artifact origin, current explicit validity, approved publisher signature and catalog admission. An unsigned candidate is never accepted by the delivery owner.

## Current evidence

The host and transport/lifecycle libraries compile on the local Windows toolchain.
Native conformance, IPC, lifecycle, package and selected-download authorization tests
pass locally. Protected installation and Windows service wiring are implemented;
elevated CI and actual endpoint acceptance remain distinct release requirements.
The bootstrap schedules collection only while inventory is selected and permitted.
Issuer/root rotation and the remaining endpoint providers still require completion.

## Signing and server-computer publication

`--artifact-origin` derives the immutable `/v1/artifacts/<sha256>/package.zip` URL
after building. `scripts/sign-native-feature.mjs --build <directory> --custody
<absolute-private-publisher.json>` signs the exact generated request and writes
`signed-module.json`. The private custody record names `credentialRoot`,
`privateKeyFile`, `publisher`, `keyId` and `rootVersion`; it belongs outside the
repository. The key must match a publisher key in the server authority.

`scripts/publish-native-artifact.mjs --build <directory> --store <absolute-store>`
writes the exact checked bytes once. The publication operator provisions the store
ACL; the serving identity needs read access only. Existing objects are never
overwritten. Admit `signed-module.json`'s entry and attestation through the scoped
catalog API, then select the desired version through management settings.

For an on-premises artifact origin, build `@one-control/artifacts` and run
`node apps/artifacts/server/local.mjs <absolute-private-config>` using the template
in `deploy/artifacts.env.example`. TLS ingress preserves the configured Host and
forwards to its loopback port. The control plane and artifact service share a
separately provisioned 32-byte read key; the publisher key stays offline. Download
capabilities expire after at most 60 seconds. A deselected or revoked device cannot
obtain a new capability; already issued reads retain that bounded lifetime.
