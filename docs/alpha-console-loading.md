# Console loading in the private alpha

The console opens only after both `/v1/me` and `/v1/devices` succeed in the current session. Jobs, audit, releases, and workspace settings load independently after that pair. Each successful optional result appears without waiting for the others.

An unsupported release route can therefore leave the authorized fleet visible. This behavior does not establish that the release module is disabled. Server registration and route admission remain separate implementation work.

## Request states and authorization

Optional sections retain these distinct states.

| State | Display and retained data |
| --- | --- |
| Idle | The manual integration read has not been requested. |
| Loading | The request is pending. Any retained snapshot keeps its original timestamp and a stale label. |
| Loaded | The response passed the console's consumed-field checks. A successful empty collection has its ordinary empty state. |
| Unsupported | The fixed endpoint returned HTTP 404, 405, or 501. The UI reports that request outcome and clears its previous snapshot. Module availability remains unknown. |
| Failed | The request failed. HTTP 403 clears the section's previous snapshot. Other failures can retain explicitly stale same-session data. |

Any HTTP 401 ends the session and clears protected data. A required identity or fleet HTTP 403 also ends the session. Optional HTTP 403 denies that section without granting or revoking separately established fleet authorization. HTTP status survives a malformed error body.

Token replacement aborts the old session. Every read result checks the captured session and refresh generation. Old successes, errors, and completion handlers cannot restore previous-user data or overwrite a newer forced refresh.

The new collection adapters check selected envelope and row fields used by the section views. These guards reject the tested malformed collections before rendering. Validation remains partial. Existing batch-review responses and some detail fields remain trusted. Complete response-schema validation and server authorization are separate responsibilities.

## Partial refresh and operations

Fleet and optional sections keep separate successful refresh times. A failed request does not advance its timestamp. The footer labels fleet freshness and distinguishes loading or unavailable optional sections from a complete collection refresh. Failed jobs do not appear as a fresh zero-operation count.

Ordinary 15-second polling skips an active refresh cycle until its optional reads settle. The fleet publishes before that settlement. Explicit refresh starts a newer read generation. The session API retains its 30-second request deadline.

Mutation busy state belongs to the issued action. An unrelated read refresh does not unlock that action or suppress its receipt or uncertainty error. No refresh retries a mutation. Protected dialogs use their actual data dependencies for invalidation. Denied jobs clear job details and approval data, and a late review response cannot reopen them.

Changes remain unavailable while their required inputs are stale or missing. Update operations require current fleet, jobs, releases, and workspace settings. Enrollment requires current fleet and workspace settings. Release registration requires current fleet and release data. Broader rings require a current workspace response that explicitly reports production. A valid production device limit can be null.

Falcon and EMA reads own their request state. Their failures remain local to the integration view. Routine fleet polling preserves their loaded results and EMA filters. Navigation away or session termination fences their pending completions. A successful server response with `configured: false` remains distinct from a failed request.

## Proposed capability metadata

This contract is a proposal for the coordinator. The console does not synthesize or implement it.

```ts
type ConsoleCapabilitiesV1 = {
  schemaVersion: 1;
  workspaceId: string;
  subject: string;
  revision: string;
  issuedAt: string;
  expiresAt: string;
  sections: Record<
    "jobs" | "audit" | "releases" | "falcon" | "ema",
    | { state: "enabled" }
    | { state: "disabled"; reasonCode: string }
    | { state: "unsupported" }
  >;
};
```

An authenticated `GET /v1/console-capabilities` could return this response with `Cache-Control: no-store`. The server derives it from actual module registration and the authenticated workspace. The subject matches the successful actor. The coordinator defines stable workspace identity, revision ownership, and expiry bounds.

Enabled describes registration. It does not grant the person permission. Disabled requires authoritative configuration. Unsupported describes an unimplemented section. Every feature route retains its ordinary authorization. The same registration owner must enforce route admission, data writes, and background work.

Failed, missing, expired, or incompatible capability metadata cannot become a disabled-module claim or an authorization grant. Contract tests need subject and workspace mismatch, expiry, revision change, unknown schema, and disabled-route bypass cases. Shared protocol files and server registration are outside this console change.

## Verification boundary

Run the rendered regression fixture from the repository root.

```powershell
node apps/console/tests/loading.browser.test.mjs
```

The fixture disables environment-file loading and OIDC configuration, binds an ephemeral IPv4 loopback server, blocks external browser requests, and supplies synthetic API responses. It covers optional failure, denial, pending and malformed responses, replacement sessions, response ordering, partial refresh, retry, dependency-specific dialog invalidation, and mutation outcomes across polling. Evidence and retained fixture caches go to `.local/alpha-work/console`.

The root test script enumerates console test files. The coordinator must invoke this new browser fixture explicitly or add it to the integrated gate. Local browser fixtures and `pnpm check` do not prove production OIDC, actual optional-module enforcement, provider access, endpoint acceptance, PostgreSQL coordination, elevated Windows storage, or deployment.
