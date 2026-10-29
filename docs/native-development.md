# Check the native bootstrap foundation

Run commands from the workspace root with Node 24 and pnpm 11.25.0. Install Go 1.27.2 before running native checks.

```powershell
pnpm install --frozen-lockfile
pnpm test:native
```

`test:native` resolves Go in this order.

1. `ONE_CONTROL_GO`, if set, names the executable. Relative paths resolve against the workspace root. An invalid explicit path fails immediately.
2. `go` on `PATH`.
3. `.tools/go/bin/go.exe` on Windows, or `.tools/go/bin/go` elsewhere.

The runner fails when no working executable exists. It sets `GOTOOLCHAIN=local` and never downloads Go. To select a specific installation in PowerShell, set the path before running the check.

```powershell
$env:ONE_CONTROL_GO = 'C:/Tools/Go/bin/go.exe'
pnpm test:native
```

The runner executes the following checks in order.

1. Verify that the Go target OS and architecture match the host.
2. Check generated wire definitions against `packages/module-contracts/schema/wire.json`.
3. Build the TypeScript contracts and planner, then check the planner's generated conformance corpus.
4. Run the module contract behavior tests and Go resolver tests.
5. Run `go -C native vet ./...` and `go -C native test ./... -count=1 -json`.
6. Inspect bootstrap dependencies. Every nonstandard package must belong to `onecontrol/native/`.
7. Build `native/cmd/oc-bootstrap` with `CGO_ENABLED=0`, `-trimpath`, and stripped symbols.
8. Execute that binary in an empty directory. Verify its empty plan, zero selected packages, unconfigured authority, and absence of created files.

Windows builds use `-ldflags=-s -w -H=windowsgui` to avoid allocating an implicit console host. Other operating systems use `-ldflags=-s -w`.

## Inspect a result

The runner writes a binary, its size and SHA-256, Go build information, dependency output, test output, and per-command exit status under `.local/orchestrate/full-build/evidence/native-checks/<platform>-<architecture>/`. `report.json` records the overall status, timings, and validated bootstrap output. A failed check exits with code 1 and retains its diagnostics.

Set `ONE_CONTROL_NATIVE_OUTPUT` to choose a different output directory. Relative paths resolve against the workspace root. The runner does not record environment variables in its report.

The [native bootstrap workflow](../.github/workflows/native-bootstrap.yml) runs these checks on actual Windows, macOS, and Ubuntu runners. It installs the pinned Go version and uploads diagnostics for seven days, including failed runs. A workflow definition is not evidence that its jobs have passed. Check the actual workflow run before reporting native OS coverage.

For foundation commit `b8390cd0bf98ba5583c64e4a58583c8b607496cb`, the [native Windows/macOS/Ubuntu run](https://github.com/chai-in/one-control/actions/runs/39304423980) and [existing verification run](https://github.com/chai-in/one-control/actions/runs/39304423920) completed successfully on 19 October 2026. The Windows agent job ran 58 tests with zero failures or skips and passed the protected artifact test. These results cover that foundation revision. They do not cover later ownership, delivery or physical endpoint work.

## Regenerate contracts and planner fixtures

After changing the normative wire schema, regenerate its outputs.

```powershell
node packages/module-contracts/scripts/generate.mjs
```

After changing the TypeScript planner, build it and regenerate the conformance fixtures.

```powershell
pnpm --filter @one-control/modules build
node packages/modules/scripts/export-fixtures.mjs
pnpm test:native
```

The generator formats its TypeScript output deterministically. Biome checks the handwritten schema, scripts, and tests. Only `packages/modules/fixtures/planner.json` is excluded because the exporter owns its exact readable serialization. The fixture drift check still compares every byte.

## Respect the remaining acceptance gates

This executable is a foundation for the native bootstrap. It has no configured enrollment authority or selected feature packages. These checks do not establish authenticated delivery, protected staging, ZIP validation, crash-safe activation, descendant containment, recovery updates, or a finished thin-agent release.

The runner's empty invocation checks output and created files. It does not independently observe the process tree or network listeners. Physical Windows and roaming Mac pilots, native protected storage, and OS containment require their own acceptance evidence. Elevated Windows protected-storage coverage remains a separate Windows CI gate.

`pnpm check` remains the JavaScript workspace gate. Before committing implementation changes, also run the locked Windows solution restore, build, and tests, plus `scripts/check-powershell.ps1`. Coordination changes require real PostgreSQL transaction tests. See [module architecture](module-architecture.md) for module boundaries and release requirements.
