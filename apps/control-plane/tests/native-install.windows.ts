import { type ChildProcess, execFile, spawn } from "node:child_process";
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

test("clean native bootstrap downloads only the selected inventory host and stops it after deselection", async () => {
  const run = randomUUID();
  const root = join(process.env.ProgramData!, `OneControlNativeAcceptance-${run}`);
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
  const candidate = join(buildRoot, "inventory");
  const now = Math.floor(Date.now() / 1000);
  await runFile(process.execPath, [
    "scripts/package-native-feature.mjs",
    "--feature",
    "inventory",
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
  const archive = await readFile(join(candidate, "inventory-0.1.0-win-x64.zip"));
  const operator = randomBytes(32).toString("base64url");
  const native = await nativeFixture(operator, {
    artifactOrigin: origin,
    artifacts: { inventory: { ...manifest.artifacts["win-x64"], files: request.files } },
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
  let child: ChildProcess | undefined;
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
                if (name !== `artifacts/${request.archiveSha256}/package.zip`) return null;
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
        allowedPermissions: Object.keys(enabled).length ? ["inventory.read"] : [],
        bootstrapVersion: "0.1.0",
      },
    });
    expect(response.statusCode, response.body).toBe(200);
  }
  async function status() {
    try {
      return JSON.parse(await readFile(join(root, "status.json"), "utf8"));
    } catch {
      return null;
    }
  }
  async function until(check: () => Promise<boolean>) {
    const deadline = Date.now() + 55_000;
    while (!(await check())) {
      if (child?.exitCode !== null || Date.now() > deadline)
        throw new Error(`Native acceptance stalled: ${JSON.stringify(await status())}`);
      await delay(250);
    }
  }
  try {
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
    const enrolled = JSON.parse(
      (await runFile(bootstrap, ["--config", config, "--enroll", invitationFile])).stdout,
    );
    await rm(invitationFile);
    child = spawn(bootstrap, ["--config", config, "--run"], {
      cwd: root,
      windowsHide: true,
      stdio: "ignore",
    });
    await until(async () => (await status())?.state === "connected");
    expect(downloads).toEqual([]);
    expect((await readdir(join(root, "modules"))).filter((name) => name.startsWith("package-"))).toEqual([]);
    await selection({ inventory: "0.1.0" });
    await until(async () => !!(await status())?.lastInventory);
    expect(downloads).toEqual([`artifacts/${request.archiveSha256}/package.zip`]);
    const [observation] = await db.query<{ kind: string }>(
      "SELECT kind FROM native_observations WHERE enrollment_id=$1",
      [enrolled.enrollmentId],
    );
    expect(observation?.kind).toBe("inventory");
    const previous = (await status()).lastSuccess;
    await selection({});
    await until(async () => {
      const current = await status();
      return current?.state === "connected" && current.lastSuccess !== previous;
    });
    expect(downloads).toHaveLength(1);
    const revoked = await app.inject({
      method: "POST",
      url: `/v1/scopes/${native.scopeId}/native-enrollments/${enrolled.enrollmentId}/revoke`,
      headers,
      payload: {},
    });
    expect(revoked.statusCode).toBe(200);
    await until(async () => (await status())?.state === "unavailable");
  } finally {
    if (child && child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill();
      await exited;
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await app.close();
    await db.close();
    await native.close();
    await rm(root, { recursive: true, force: true });
    await rm(buildRoot, { recursive: true, force: true });
  }
});
