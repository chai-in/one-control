import { lstat, open, readFile, realpath } from "node:fs/promises";
import { createServer } from "node:http";
import { isAbsolute, join, relative } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { pathToFileURL } from "node:url";
import { parseEnv } from "node:util";
import { serveArtifact } from "../dist/worker.js";

// Ingress terminates TLS and forwards the original host to this loopback-only
// service. The artifact process has read-only access to the publication store.
export async function localArtifactServer({ root, host, secret }) {
  if (
    !isAbsolute(root) ||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
      host,
    ) ||
    !/^[A-Za-z0-9_-]{43}$/.test(secret)
  )
    throw new Error("Invalid artifact service configuration");
  if (!(await lstat(root)).isDirectory() || (await lstat(root)).isSymbolicLink())
    throw new Error("An ordinary artifact directory is required");
  const canonicalRoot = await realpath(root);
  async function object(key) {
    if (!/^artifacts\/[a-f0-9]{64}\/(?:package\.zip|one-control-agent-\d+\.\d+\.\d+\.msi)$/.test(key))
      return null;
    const file = join(canonicalRoot, ...key.split("/"));
    try {
      const canonical = await realpath(file);
      const child = relative(canonicalRoot, canonical);
      if (child.startsWith("..") || isAbsolute(child) || canonical !== file) return null;
      const handle = await open(file, "r");
      const stats = await handle.stat();
      if (!stats.isFile()) {
        await handle.close();
        return null;
      }
      return { handle, size: stats.size };
    } catch (error) {
      if (error.code === "ENOENT" || error.code === "ENOTDIR") return null;
      throw error;
    }
  }
  const environment = {
    ARTIFACT_PUBLIC_HOST: host,
    ARTIFACT_READ_KEY: secret,
    ARTIFACT_NATIVE_PACKAGES_ENABLED: "true",
    ARTIFACTS: {
      async head(key) {
        const stored = await object(key);
        if (!stored) return null;
        await stored.handle.close();
        return { size: stored.size };
      },
      async get(key, options) {
        const stored = await object(key);
        if (!stored) return null;
        const range = options?.range;
        const stream = stored.handle.createReadStream(
          range ? { start: range.offset, end: range.offset + range.length - 1 } : {},
        );
        return { size: stored.size, body: Readable.toWeb(stream) };
      },
    },
  };
  const server = createServer(async (incoming, outgoing) => {
    outgoing.setHeader("Cache-Control", "no-store");
    outgoing.setHeader("X-Content-Type-Options", "nosniff");
    outgoing.setHeader("Referrer-Policy", "no-referrer");
    if (incoming.headers.host !== host || !incoming.url?.startsWith("/")) {
      outgoing.writeHead(404).end();
      return;
    }
    try {
      const response = await serveArtifact(
        new Request(`https://${host}${incoming.url}`, {
          method: incoming.method,
          headers: incoming.headers.range ? { range: incoming.headers.range } : {},
        }),
        environment,
      );
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      if (response.body) await pipeline(Readable.fromWeb(response.body), outgoing);
      else outgoing.end();
    } catch {
      // Capability URLs and filesystem errors must never enter access logs.
      if (!outgoing.headersSent) outgoing.writeHead(503).end();
      else outgoing.destroy();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return server;
}

async function main() {
  const filename = process.argv[2];
  if (!filename || !isAbsolute(filename))
    throw new Error("An absolute artifact configuration file is required");
  const config = parseEnv(await readFile(filename, "utf8"));
  if (!isAbsolute(config.ARTIFACT_READ_KEY_FILE ?? "") || !isAbsolute(config.CREDENTIAL_ROOT ?? ""))
    throw new Error("Explicit private key custody is required");
  const credentialRoot = await realpath(config.CREDENTIAL_ROOT);
  const keyFile = await realpath(config.ARTIFACT_READ_KEY_FILE);
  const child = relative(credentialRoot, keyFile);
  if (child.startsWith("..") || isAbsolute(child))
    throw new Error("Artifact key must be inside credential custody");
  const key = await readFile(keyFile);
  if (key.length !== 32) throw new Error("Invalid artifact key size");
  const port = Number(config.ARTIFACT_PORT);
  if (!Number.isInteger(port) || port < 1024 || port > 65535)
    throw new Error("Explicit artifact loopback port required");
  const server = await localArtifactServer({
    root: config.ARTIFACT_ROOT,
    host: config.ARTIFACT_PUBLIC_HOST,
    secret: key.toString("base64url"),
  });
  key.fill(0);
  server.on("error", () => {
    process.stderr.write("Artifact service failed\n");
    process.exitCode = 1;
  });
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close());
  server.listen(port, "127.0.0.1", () =>
    process.stdout.write("Artifact service ready on configured loopback port\n"),
  );
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch(() => {
    process.stderr.write("Artifact service configuration failed\n");
    process.exitCode = 1;
  });
