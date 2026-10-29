import { execFile } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { networkInterfaces } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import type { InjectOptions } from "fastify";
import { expect, test } from "vitest";
import { serveArtifact } from "../../artifacts/src/worker.js";
import { buildApp } from "../src/app.js";
import { parseConfig } from "../src/config.js";
import { hash } from "../src/security.js";
import { openTestDatabase } from "./database-fixture.js";
import { nativeFixture } from "./native-fixture.js";

const execute = promisify(execFile);
const repository = resolve("../..");

test("signed SYSTEM bootstrap downloads selected hosts, preserves restart state, and executes indexing status", async () => {
  const run = randomUUID();
  const root = join(process.env.ProgramData!, `OneControlNativeAcceptance-${run}`);
  const serviceRoot = join(process.env.ProgramData!, "OneControlNative");
  const buildRoot = join(repository, ".local/native-acceptance", run);
  await mkdir(buildRoot, { recursive: true });
  const bootstrap = join(buildRoot, "oc-bootstrap.exe");
  const go = process.env.ONE_CONTROL_GO ?? "go";
  const runFile = (file: string, args: string[]) =>
    execute(file, args, {
      cwd: repository,
      windowsHide: true,
      timeout: 120_000,
      maxBuffer: 1024 * 1024,
      env: { ...process.env, GOTOOLCHAIN: "local" },
    });
  await runFile(go, [
    "-C",
    "native",
    "build",
    "-trimpath",
    "-buildvcs=false",
    "-o",
    bootstrap,
    "./cmd/oc-bootstrap",
  ]);
  await runFile(bootstrap, ["--prepare-root", root]);
  const ip = Object.values(networkInterfaces())
    .flat()
    .find(
      (item) =>
        item?.family === "IPv4" &&
        !item.internal &&
        /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(item.address),
    )?.address;
  if (!ip) throw new Error("Native acceptance needs an assigned private IPv4 interface");
  const origin = `https://${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const artifacts: Record<
    string,
    { url: string; sha256: string; size: number; files: { path: string; sha256: string; size: number }[] }
  > = {};
  const archives = new Map<string, Buffer>();
  for (const feature of ["inventory", "indexing"]) {
    const candidate = join(buildRoot, feature);
    await runFile(process.execPath, [
      "scripts/package-native-feature.mjs",
      "--feature",
      feature,
      "--version",
      "0.1.0",
      "--platform",
      "win-x64",
      "--output",
      candidate,
      "--artifact-origin",
      origin,
      "--publisher",
      "fixture",
      "--issued-at",
      String(now - 1),
      "--expires-at",
      String(now + 3600),
    ]);
    const request = JSON.parse(await readFile(join(candidate, "publisher-request.json"), "utf8"));
    const manifest = JSON.parse(await readFile(join(candidate, "manifest.json"), "utf8"));
    const archive = await readFile(join(candidate, `${feature}-0.1.0-win-x64.zip`));
    artifacts[feature] = { ...manifest.artifacts["win-x64"], files: request.files };
    archives.set(`artifacts/${request.archiveSha256}/package.zip`, archive);
  }
  const operator = randomBytes(32).toString("base64url");
  const native = await nativeFixture(operator, {
    artifactOrigin: origin,
    features: ["inventory", "indexing"],
    artifacts,
  });
  const db = await openTestDatabase();
  const app = await buildApp(
    db,
    parseConfig({
      NODE_ENV: "test",
      DEV_OPERATOR_TOKEN: operator,
      DEV_APPROVER_TOKEN: randomBytes(32).toString("base64url"),
      ...native.config,
    }),
  );
  const headers = { authorization: `Bearer ${operator}` };
  const downloads: string[] = [];
  const serviceFixture = (action: string, args: string[] = []) =>
    runFile("pwsh", [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      "scripts/tests/native-service-fixture.ps1",
      "-Action",
      action,
      "-FixtureDirectory",
      root,
      ...args,
    ]);
  await runFile("pwsh", [
    "-NoProfile",
    "-NonInteractive",
    "-File",
    "scripts/tests/native-test-certificate.ps1",
    "-Directory",
    root,
    "-IPAddress",
    ip,
  ]);
  const cert = await readFile(join(root, "tls-certificate.pem"));
  const key = await readFile(join(root, "tls-private.pem"));
  const server = createServer({ key, cert }, async (incoming, outgoing) => {
    try {
      if (incoming.url?.startsWith("/v1/artifacts/")) {
        const response = await serveArtifact(
          new Request(`${origin}${incoming.url}`, { method: incoming.method ?? "GET" }),
          {
            ARTIFACT_PUBLIC_HOST: ip,
            ARTIFACT_READ_KEY: native.artifactKey,
            ARTIFACT_NATIVE_PACKAGES_ENABLED: "true",
            ARTIFACTS: {
              async head() {
                return null;
              },
              async get(name) {
                downloads.push(name);
                const archive = archives.get(name);
                if (!archive) return null;
                return {
                  size: archive.length,
                  body: new ReadableStream({
                    start(controller) {
                      controller.enqueue(archive);
                      controller.close();
                    },
                  }),
                };
              },
            },
          },
        );
        outgoing.writeHead(response.status, Object.fromEntries(response.headers));
        outgoing.end(Buffer.from(await response.arrayBuffer()));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
      const response = await app.inject({
        method: (incoming.method ?? "GET") as NonNullable<InjectOptions["method"]>,
        url: incoming.url!,
        headers: incoming.headers,
        ...(chunks.length ? { payload: Buffer.concat(chunks) } : {}),
      });
      outgoing.writeHead(response.statusCode, response.headers);
      outgoing.end(response.rawPayload);
    } catch {
      outgoing.writeHead(500).end();
    }
  });
  async function selection(enabled: Record<string, string>) {
    const version = (await app.inject({ url: `/v1/scopes/${native.scopeId}/modules`, headers })).json()
      .version;
    const [row] = await db.query<{ catalog_id: string }>(
      "SELECT catalog_id FROM native_selections WHERE scope_id=$1",
      [native.scopeId],
    );
    const response = await app.inject({
      method: "PUT",
      url: `/v1/scopes/${native.scopeId}/native-modules/selection`,
      headers,
      payload: {
        expectedVersion: version,
        platform: "win-x64",
        catalogId: row!.catalog_id,
        enabled,
        disabled: [],
        allowedPermissions: Object.keys(enabled).map((id) =>
          id === "inventory" ? "inventory.read" : "indexing.manage",
        ),
        bootstrapVersion: "0.1.0",
      },
    });
    expect(response.statusCode, response.body).toBe(200);
  }
  async function status() {
    try {
      return JSON.parse(await readFile(join(serviceRoot, "status.json"), "utf8"));
    } catch {
      return null;
    }
  }
  async function until(check: () => Promise<boolean>) {
    const deadline = Date.now() + 55_000;
    while (!(await check())) {
      if (Date.now() > deadline)
        throw new Error(`Native acceptance stalled: ${JSON.stringify(await status())}`);
      await delay(250);
    }
  }
  try {
    await serviceFixture("prepare", ["-BootstrapFile", bootstrap]);
    server.listen(443, ip);
    await once(server, "listening");
    await native.prepare(app);
    await selection({});
    const identity = JSON.parse((await runFile(bootstrap, ["--identity"])).stdout);
    const token = randomBytes(32).toString("base64url");
    const invitation = await app.inject({
      method: "POST",
      url: `/v1/scopes/${native.scopeId}/native-invitations`,
      headers,
      payload: {
        tokenHash: hash(token),
        hostname: "isolated-native-acceptance",
        machineId: identity.machineId,
        platform: identity.platform,
      },
    });
    expect(invitation.statusCode, invitation.body).toBe(201);
    const config = join(root, "installation.json");
    await writeFile(
      config,
      JSON.stringify({
        schemaVersion: 1,
        origin,
        deviceId: invitation.json().deviceId,
        machineId: identity.machineId,
        platform: identity.platform,
        ...native.installationTrust,
        artifactNetworks: { [origin]: [`${ip}/32`] },
        tlsRootsPem: cert.toString(),
        reconcileSeconds: 15,
        inventorySeconds: 60,
      }),
    );
    const invitationFile = join(root, "invitation.json");
    await writeFile(invitationFile, JSON.stringify({ token }));
    await serviceFixture("install", [
      "-BootstrapFile",
      bootstrap,
      "-ConfigurationFile",
      config,
      "-InvitationFile",
      invitationFile,
    ]);
    await rm(invitationFile);
    const [enrolled] = await db.query<{ enrollmentId: string }>(
      'SELECT id AS "enrollmentId" FROM native_enrollments WHERE device_id=$1 AND revoked_at IS NULL',
      [invitation.json().deviceId],
    );
    expect(enrolled).toBeDefined();
    await until(async () => (await status())?.state === "connected");
    expect(downloads).toEqual([]);
    expect(
      (await readdir(join(serviceRoot, "modules"))).filter((name) => name.startsWith("package-")),
    ).toEqual([]);
    await selection({ inventory: "0.1.0" });
    await until(async () => !!(await status())?.lastInventory);
    expect(downloads).toEqual([`artifacts/${artifacts.inventory!.sha256}/package.zip`]);
    const [observation] = await db.query<{ kind: string }>(
      "SELECT kind FROM native_observations WHERE enrollment_id=$1",
      [enrolled!.enrollmentId],
    );
    expect(observation?.kind).toBe("inventory");
    const beforeRestart = (await status()).lastSuccess;
    await serviceFixture("restart");
    await until(async () => {
      const current = await status();
      return current?.state === "connected" && current.lastSuccess !== beforeRestart;
    });
    expect(downloads).toHaveLength(1);
    expect(
      await db.query("SELECT id FROM native_enrollments WHERE device_id=$1", [invitation.json().deviceId]),
    ).toHaveLength(1);
    await selection({ indexing: "0.1.0" });
    const operation = await app.inject({
      method: "POST",
      url: "/v1/batches",
      headers: { ...headers, "idempotency-key": randomUUID() },
      payload: {
        targets: [invitation.json().deviceId],
        ring: "canary",
        command: { kind: "indexing.status" },
        startsAt: new Date(Date.now() - 1000).toISOString(),
        endsAt: new Date(Date.now() + 3600000).toISOString(),
      },
    });
    expect(operation.statusCode, operation.body).toBe(201);
    await until(async () => {
      const [job] = await db.query<{ state: string }>("SELECT state FROM jobs WHERE batch_id=$1", [
        operation.json().batchId,
      ]);
      return job?.state === "succeeded";
    });
    expect(downloads).toEqual([
      `artifacts/${artifacts.inventory!.sha256}/package.zip`,
      `artifacts/${artifacts.indexing!.sha256}/package.zip`,
    ]);
    const [indexResult] = await db.query<{ result: { after: { service: string; pauseMechanism: string } } }>(
      "SELECT result FROM jobs WHERE batch_id=$1",
      [operation.json().batchId],
    );
    expect(indexResult?.result.after.service).toBeTypeOf("string");
    expect(indexResult?.result.after.pauseMechanism).toBe("service-stop-fallback");
    const previous = (await status()).lastSuccess;
    await selection({});
    await until(async () => {
      const current = await status();
      return current?.state === "connected" && current.lastSuccess !== previous;
    });
    expect(downloads).toHaveLength(2);
    const revoked = await app.inject({
      method: "POST",
      url: `/v1/scopes/${native.scopeId}/native-enrollments/${enrolled!.enrollmentId}/revoke`,
      headers,
      payload: {},
    });
    expect(revoked.statusCode).toBe(200);
    await until(async () => (await status())?.state === "unavailable");
  } finally {
    if ((await readdir(root)).includes("service-fixture.json")) await serviceFixture("cleanup");
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await app.close();
    await db.close();
    await native.close();
    await rm(root, { recursive: true, force: true });
    await rm(buildRoot, { recursive: true, force: true });
  }
});
