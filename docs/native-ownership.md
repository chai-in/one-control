# Native authority and Windows child ownership

`native/internal/ownership` gives one writer kernel ownership of a stable lock file. `authority.OpenStore` acquires that ownership before it reads the authority journal. The existing checksummed append, flush, monotonic checkpoint validation, and compare-and-swap remain the persistence boundary.

On Windows, ownership is an exclusive one-byte `LockFileEx` lock. The file handle is non-inheritable and denies delete sharing. Linux and macOS use `flock` on a close-on-exec file descriptor. Both `ownership.Acquire(ctx, path)` and `authority.OpenStore(ctx, path)` use the caller's explicit deadline. Already canceled, elapsed or unbounded callers never open the lock file. Acquisition retries actual kernel contention while the caller remains live. Cancellation and expiry return plain `context.Canceled` or `context.DeadlineExceeded`; actual platform errors remain platform errors. A context error alone makes no claim that another writer exists.

Acquisition checks cancellation and the effective absolute deadline before opening, after synchronous opening, before retries and after successful kernel locking. It closes the exact handle when a caller has terminated at those boundaries. Context cancellation cannot interrupt synchronous file opening or close, journal validation, flushing or scheduler delays. The deadline governs willingness to retry and transfer ownership; it does not cap total wall-clock time. Cancellation can still occur immediately after the final observation.

`Close` releases the kernel owner and keeps the file. Process death also releases ownership, but cleanup need not finish immediately. A recovery caller supplies its startup context and must obtain actual kernel ownership before reading the journal. Process exit, stale-file deletion and PID comparisons do not authorize a new writer. The [Windows lock reference](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex) describes resource-dependent cleanup after termination.

The lock coordinates writers that use the same stable file. It does not establish a private directory, prevent a hostile directory owner from replacing files on Unix, or resist privileged disk rollback. Protected path and ACL adapters remain required. A flushed append does not establish power-loss directory durability.

## Candidate child states

`native/internal/processhost.Start` launches a fixed host executable in `Candidate` state. The executable path is absolute. The instance is a 32-byte nonce encoded as 64 lowercase hexadecimal characters. The adapter passes exactly `--one-control-host-v1 <instance>`. It has no shell, environment passthrough, provider selection, or command router.

The caller supplies readiness, operation, and stop timeouts. Each timeout is positive and at most 30 seconds. A stop can use separate bounded periods for its response, graceful job exit, and forced job exit.

| State | Entry condition | Permitted lifecycle work |
| --- | --- | --- |
| `Candidate` | Suspended creation inside the owned job, membership verification, and resume succeeded. | Await readiness or stop. |
| `Ready` | A matching Ready response arrived before the readiness deadline. | Activate or stop. |
| `Active` | A matching activation response arrived. | Check health or stop. |
| `Healthy` | A matching health response arrived. | Check health or stop. |
| `Stopped` | The job has no active processes and the retained root process handle signals exit. | Collect or repeat stop. |
| `ContainmentUnknown` | Termination or the kernel exit proof failed. | Report the uncertainty and block collection. |

Ready does not authorize feature work. The separate [generation owner](native-lifecycle.md) must commit the active generation before calling `Activate`. This adapter does not implement that journal or make an activation authorization decision. A protocol error or timeout triggers forced teardown. A successful `Stop` reports whether teardown required force. An unknown result retains its handles, rejects later lifecycle calls, and keeps `CanCollect` false.

## Windows ownership boundary

The Windows record retains the exact process, primary thread, Job Object, and control-pipe handles. A PID is diagnostic data in the development fixture and never authorizes termination.

`CreateProcessW` starts the executable suspended with a Unicode environment containing only `SystemRoot`. `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` permits only the child's input and output pipe handles. The parent pipe ends, lock handle, process handles, and unnamed Job Object are non-inheritable. The child's stdout and stderr share the protocol channel.

The Job Object has `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Breakaway permissions are absent. `PROC_THREAD_ATTRIBUTE_JOB_LIST` assigns the job during process creation, closing the controller-death gap before a later assignment. This creation attribute requires Windows 10 or Windows Server 2016 or newer. There is no fallback to late assignment. `IsProcessInJob` must prove membership before `ResumeThread` returns a prior suspension count of one. A failure before resume terminates the owned process, terminates any assigned job members, waits for the root and job-empty proof, and closes all owned handles. A failed proof returns `ErrContainment`. The [Windows process-attribute reference](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) defines the creation attribute.

Normal stop first requests a graceful exit. A missing response, a hung host, or a remaining descendant causes `TerminateJobObject`. Successful teardown requires both zero active job processes and a signaled retained root handle. Job accounting can reach zero before the root handle signals, so the adapter waits for both within the bound. Owner death closes the non-inherited Job Object handle and the kernel terminates its members.

This is process-tree ownership for approved executable hosts. It is not a security sandbox or a protected installation adapter. The caller still needs verified package bytes, publisher authority, platform privilege restrictions, and a protected executable path.

## Fixed control protocol

Each frame is a four-byte big-endian length followed by 1 through 4,096 bytes of canonical JSON. A message contains exactly `version`, `type`, `instance`, and `sequence` in that order. Version is `1`. The instance matches the launch nonce. Ready uses sequence zero. Each command increments the sequence, and its response must match that sequence. Duplicate fields, extra fields, malformed JSON, noncanonical encodings, oversized frames, wrong instances, stale responses, and unexpected response types fail closed.

The request and response pairs are `activate` and `active`, `health` and `healthy`, and `stop` and `stopped`. The host sends `ready` before any request. The channel is private to the owned child. A host must remain inert before activation. The harmless development host remains alive and inert on control EOF, so its owner-death test cannot pass through cooperative EOF exit.

## Verification boundary

Run these commands from the workspace root with the local Go toolchain and Node 24 on PATH.

```powershell
go -C native vet ./...
go -C native test ./... -count=1
pnpm test:native
```

Windows tests compile and execute `native/internal/processhost/testdata/host`. The fixture performs no endpoint management. Tests exercise real competing lock owners, process death, stable lock-file identity, flushed checkpoint recovery, checksum and torn-frame rejection, suspended creation, denied assignment before resume, handle exclusion, the environment allowlist, breakaway rejection, activation sequencing, stale health responses, readiness and operation timeouts, forced stop, and orphaned descendants.

The owner-death test queries the actual job process list and retains every member's process handle. It verifies membership and live state, closes its query-only job handle, kills the owner through its retained process object, and waits for every member to signal exit. Stop tests also require the actual job-empty condition. A terminate-only job handle forces a query failure and proves that unknown containment blocks successful stop and collection.

The lock tests run on the current native operating system. Linux and macOS host launch returns `ErrUnsupported`; no process-group substitute exists. [Current ownership CI](https://github.com/chai-in/one-control/actions/runs/39308046452) passes native lock and contract checks on Windows, macOS and Ubuntu and executes this process adapter on Windows. Cross-compilation cannot satisfy native execution gates.

The empty bootstrap imports neither this process adapter nor a provider. Atomic creation closes the old pre-assignment orphan window. It does not prove that a restarted controller can recover custody after losing its handles. The [generation pilot](native-lifecycle.md) preserves unknown custody and blocks conflicting activation and collection. The separate [package library](native-packages.md) stages verified inert bytes and grants no execution authority. The [ownership-parent Verify run](https://github.com/chai-in/one-control/actions/runs/39308046750) executes 58 imported Windows tests with no skips; it predates the atomic creation and generation changes. New native protected-root custody, power-loss behavior, platform services, native Unix containment and physical endpoint acceptance remain open.
