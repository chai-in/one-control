import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const repository = fileURLToPath(new URL("../", import.meta.url));

export function resolveGo({ environment = process.env, root = repository, run = spawnSync } = {}) {
  const env = { ...environment, GOTOOLCHAIN: "local" };
  const explicit = environment.ONE_CONTROL_GO;
  const candidates =
    explicit === undefined
      ? ["go", join(root, ".tools", "go", "bin", process.platform === "win32" ? "go.exe" : "go")]
      : [resolve(root, explicit)];
  if (explicit !== undefined && explicit.trim() === "") {
    throw new Error("ONE_CONTROL_GO must name a Go executable.");
  }
  for (const command of candidates) {
    const result = run(command, ["version"], { env, encoding: "utf8", windowsHide: true, timeout: 30_000 });
    if (result.status === 0 && /^go version go\d+\.\d+/u.test(result.stdout ?? "")) {
      return { command, version: result.stdout.trim(), env };
    }
  }
  throw new Error(
    explicit === undefined
      ? "Go is required. Set ONE_CONTROL_GO, put go on PATH, or install it in .tools/go/bin. No toolchain was downloaded."
      : `ONE_CONTROL_GO is not a working Go executable: ${candidates[0]}`,
  );
}

export function checkNative() {
  const output = resolve(
    repository,
    process.env.ONE_CONTROL_NATIVE_OUTPUT ??
      `.local/orchestrate/full-build/evidence/native-checks/${process.platform}-${process.arch}`,
  );
  mkdirSync(join(output, "steps"), { recursive: true });
  const report = {
    schemaVersion: 1,
    startedAt: new Date().toISOString(),
    platform: process.platform,
    architecture: process.arch,
    nodeVersion: process.version,
    status: "running",
    steps: [],
  };
  const save = () => writeFileSync(join(output, "report.json"), `${JSON.stringify(report, null, 2)}\n`);
  const run = (name, command, args, options = {}) => {
    console.log(`Native check ${name}`);
    const started = performance.now();
    const result = spawnSync(command, args, {
      cwd: repository,
      env: process.env,
      encoding: "utf8",
      windowsHide: true,
      timeout: 300_000,
      maxBuffer: 32 * 1024 * 1024,
      ...options,
    });
    const prefix = `${String(report.steps.length + 1).padStart(2, "0")}-${name}`;
    writeFileSync(join(output, "steps", `${prefix}.stdout.log`), result.stdout ?? "");
    writeFileSync(join(output, "steps", `${prefix}.stderr.log`), result.stderr ?? "");
    report.steps.push({
      name,
      command,
      args,
      status: result.status,
      signal: result.signal,
      error: result.error?.message,
      elapsedMs: Math.round(performance.now() - started),
    });
    save();
    if (result.status !== 0 || result.error) {
      process.stderr.write(result.stderr ?? "");
      process.stdout.write(result.stdout ?? "");
      throw new Error(
        `${name} failed with exit ${result.status}: ${result.error?.message ?? result.signal ?? "see logs"}`,
      );
    }
    return result.stdout;
  };
  save();
  try {
    const go = resolveGo();
    report.goVersion = go.version;
    report.goExecutable = go.command;
    const goEnvironment = JSON.parse(
      run(
        "go-environment",
        go.command,
        ["env", "-json", "GOHOSTOS", "GOHOSTARCH", "GOOS", "GOARCH", "GOVERSION"],
        { env: go.env },
      ),
    );
    assert.equal(goEnvironment.GOOS, goEnvironment.GOHOSTOS, "Native checks must execute on the target OS.");
    assert.equal(
      goEnvironment.GOARCH,
      goEnvironment.GOHOSTARCH,
      "Native checks must execute on the target architecture.",
    );
    run("wire-drift", process.execPath, ["packages/module-contracts/scripts/generate.mjs", "--check"]);
    run("contract-build", process.execPath, [
      "node_modules/typescript/bin/tsc",
      "-p",
      "packages/module-contracts/tsconfig.json",
    ]);
    run("planner-build", process.execPath, [
      "node_modules/typescript/bin/tsc",
      "-p",
      "packages/modules/tsconfig.json",
    ]);
    run("fixture-drift", process.execPath, ["packages/modules/scripts/export-fixtures.mjs", "--check"]);
    const contractTests = readdirSync(join(repository, "packages/module-contracts/tests"))
      .filter((name) => name.endsWith(".test.mjs"))
      .sort()
      .map((name) => `packages/module-contracts/tests/${name}`);
    assert.ok(contractTests.length > 0, "Module contract behavior tests are required.");
    run("contract-tests", process.execPath, ["--test", ...contractTests]);
    run("tooling-tests", process.execPath, ["--test", "scripts/tests/native-tooling.test.mjs"]);
    run("go-vet", go.command, ["-C", "native", "vet", "./..."], { env: go.env });
    run("go-test", go.command, ["-C", "native", "test", "./...", "-count=1", "-json"], { env: go.env });
    for (const feature of ["inventory", "rdp", "wake-relay", "windows-updates"]) {
      const directory = `modules/${feature}/native`;
      run(`${feature}-vet`, go.command, ["-C", directory, "vet", "./..."], { env: go.env });
      run(`${feature}-test`, go.command, ["-C", directory, "test", "./...", "-count=1", "-json"], {
        env: go.env,
      });
    }
    run(
      "lifecycle-fixture-tests",
      go.command,
      [
        "-C",
        "native",
        "test",
        "-tags=onecontrol_lifecycle_fixture",
        "./internal/lifecycle",
        "-count=1",
        "-json",
      ],
      { env: go.env },
    );
    const productionPackages = JSON.parse(
      run("production-package-files", go.command, ["-C", "native", "list", "-json", "./internal/packages"], {
        env: go.env,
      }),
    );
    assert.ok(!productionPackages.GoFiles.includes("fixture_lifecycle.go"));
    assert.ok(productionPackages.IgnoredGoFiles.includes("fixture_lifecycle.go"));
    const dependencies = run(
      "bootstrap-dependencies",
      go.command,
      [
        "-C",
        "native",
        "list",
        "-deps",
        "-f",
        "{{if not .Standard}}{{.ImportPath}}{{end}}",
        "./cmd/oc-bootstrap",
      ],
      { env: go.env },
    );
    for (const dependency of dependencies.trim().split(/\r?\n/u).filter(Boolean)) {
      assert.ok(
        [
          "onecontrol/native/cmd/oc-bootstrap",
          "onecontrol/native/internal/contracts",
          "onecontrol/native/internal/selection",
          "onecontrol/native/internal/bootstrap",
          "onecontrol/native/internal/controlplane",
          "onecontrol/native/internal/protectedstore",
          "onecontrol/native/internal/authority",
          "onecontrol/native/internal/lifecycle",
          "onecontrol/native/internal/packages",
          "onecontrol/native/internal/ownership",
          "onecontrol/native/internal/processhost",
          "onecontrol/native/internal/processhost/internal/custody",
          "golang.org/x/sys/windows",
          "golang.org/x/sys/windows/registry",
          "golang.org/x/sys/windows/svc",
        ].includes(dependency),
        `Unexpected bootstrap dependency: ${dependency}`,
      );
    }
    const binary = join(output, process.platform === "win32" ? "oc-bootstrap.exe" : "oc-bootstrap");
    const flags = process.platform === "win32" ? "-s -w -H=windowsgui" : "-s -w";
    run(
      "bootstrap-build",
      go.command,
      ["-C", "native", "build", "-trimpath", `-ldflags=${flags}`, "-o", binary, "./cmd/oc-bootstrap"],
      { env: { ...go.env, CGO_ENABLED: "0" } },
    );
    run("bootstrap-build-info", go.command, ["version", "-m", binary], { env: go.env });
    report.binary = {
      file: binary,
      bytes: statSync(binary).size,
      sha256: createHash("sha256").update(readFileSync(binary)).digest("hex"),
      cgoEnabled: false,
      linkerFlags: flags,
    };
    const workspace = mkdtempSync(join(output, "empty-workspace-"));
    try {
      const result = JSON.parse(run("empty-bootstrap", binary, [], { cwd: workspace, timeout: 30_000 }));
      assert.equal(result.mode, "empty-selection-foundation");
      assert.equal(result.selectedPackages, 0);
      assert.equal(result.authorityConfigured, false);
      assert.equal(
        result.platform,
        `${{ win32: "win", darwin: "osx", linux: "linux" }[process.platform]}-${{ x64: "x64", arm64: "arm64" }[process.arch]}`,
      );
      assert.ok(Number.isSafeInteger(result.pid) && result.pid > 0);
      assert.deepEqual(result.plan, { packages: [], deactivate: [], removalCandidates: [] });
      assert.deepEqual(readdirSync(workspace), [], "Empty bootstrap must not create feature files.");
      report.emptyBootstrap = result;
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error = error.message;
    throw error;
  } finally {
    report.finishedAt = new Date().toISOString();
    save();
    console.log(`Native diagnostics ${join(output, "report.json")}`);
  }
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    checkNative();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
