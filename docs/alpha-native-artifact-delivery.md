# Native artifact read delivery

This reference describes the bounded artifact Worker component. It does not establish an installable native release or accepted production delivery.

## Routes and issuers

| Artifact | Exact request path | Storage key | Complete size ceiling | Media type |
| --- | --- | --- | --- | --- |
| Native ZIP | `/v1/artifacts/<sha256>/package.zip` | `artifacts/<sha256>/package.zip` | 67,108,864 bytes | `application/zip` |
| Agent MSI | `/v1/artifacts/<sha256>/one-control-agent-<version>.msi` | `artifacts/<sha256>/one-control-agent-<version>.msi` | 2,147,483,648 bytes | `application/octet-stream` |

`sha256` is exactly 64 lowercase hexadecimal characters. MSI versions contain three canonical decimal components with maxima 255, 255, and 65535. Native delivery accepts only the fixed `package.zip` filename. Arbitrary ZIP filenames, extensions, nested paths, and module or platform names are unavailable.

The shared native `Artifact` contract accepts generic strict HTTPS URLs. It does not prescribe a ZIP filename. `package.zip` is this service's restricted convention. Module identity, version, platform, publisher, and layout remain in the existing signed catalog and publisher attestation.

`issueReadUrl` retains its existing `origin`, `sha256`, `version`, `size`, and `expires` inputs. `issueNativePackageReadUrl` accepts `origin`, `sha256`, `size`, and `expires`. Both receive the canonical read secret and trusted current time separately. Neither accepts an arbitrary path.

## Read capability

Both issuers use the existing HMAC-SHA256 authorization. Its UTF-8 payload contains these fields separated by a newline, with no final newline.

```text
one-control-artifact-read-v1
<hostname>
<exact path>
<e>
<n>
```

The query has exactly one each of `e`, `n`, and `s`, with no additional parameters. `e` is a positive canonical decimal Unix expiry in seconds. `n` is a positive canonical decimal complete byte size within the route's ceiling. Expiry must be later than the current second and no more than 24 hours away. `s` and the 256-bit read key use canonical unpadded base64url.

Only GET and HEAD share this capability. The URL must use HTTPS and the exact configured hostname, with no nondefault port, credentials, or fragment. Authorization precedes resolution of the `ARTIFACTS` binding. The digest in the immutable path is signed. The Worker neither recomputes that digest nor verifies publisher signatures or ZIP contents.

## Availability and responses

Native reads require `ARTIFACT_NATIVE_PACKAGES_ENABLED` to equal the string `true`. The template sets it to `false`. Absent, false, or malformed values deny native access before storage. MSI reads remain available under their existing authorization. This flag controls service availability. It does not enforce per-device module selection, revocation, or activation policy.

Authorized client Range headers return 416, including empty or malformed ranges, on both GET and HEAD. Invalid authorization still returns 404. HEAD reads object metadata and returns no body. Native GET requests R2 range offset zero and length `n + 1`, checks the complete object metadata size against `n`, and passes the R2 body directly to the response. It does not buffer or re-hash the archive. MSI GET retains its existing storage read. The [R2 Workers API reference](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/#ranged-reads) defines these range options.

The handler constructs successful responses with status 200, the route's exact media type, a complete `Content-Length` header, and an attachment disposition with the fixed filename. It includes `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. Provider HTTP metadata, redirects, Content-Encoding, and Content-Range are not copied. The target runtime controls actual HTTP framing.

Missing objects return empty 404 responses. Storage exceptions, missing GET bodies, and invalid or mismatched complete size metadata return empty 503 responses. Size mismatch cancels the stored body. Stream failures after response creation reject body consumption. They cannot replace the already returned status.

## Integration and acceptance limits

The central protected issuer currently wraps MSI Authenticode validation. It does not publish or authorize native archives through this new issuer. Root integration still requires an approved archive publisher and catalog binding, immutable publication with exact readback, protected capability output, and coherent renewed catalog authority. Those changes remain outside this component.

The native downloader independently checks publisher evidence, archive binding, byte length, SHA-256, ZIP contents, and delivery limits. Its default compressed archive ceiling remains 16 MiB. The service's 64 MiB ceiling does not change that default.

The local policy and service tests run in Node with storage fixtures. They establish request authorization, exact fixture bytes, bounded storage arguments, headers, and error behavior. They do not establish actual Workers/R2 framing. [Workers Response documentation](https://developers.cloudflare.com/workers/runtime-apis/response/#set-the-content-length-header) states that the runtime controls Content-Length and ignores manually set values. The target runtime must still prove exact Content-Length, no Transfer-Encoding or Content-Encoding, and successful delivery through the real native TLS downloader before deployment acceptance. Passing a direct R2 body preserves the existing approach but is not proof of that gate.

Deployment requires explicit fresh configuration and bindings. This change does not alter the account, bucket, compatibility date, or deployment target. The existing template has observability disabled and no traces configured. Sanitized request telemetry and capability URL confidentiality remain deployment review items. Raw capability URLs and read secrets must not appear in logs.
