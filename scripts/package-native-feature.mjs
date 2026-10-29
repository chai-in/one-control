import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { crc32 } from "node:zlib";
import { resolveGo } from "./check-native.mjs";

const repository = fileURLToPath(new URL("../", import.meta.url));
const { values } = parseArgs({
  options: {
    feature: { type: "string" },
    version: { type: "string" },
    platform: { type: "string" },
    output: { type: "string" },
    "artifact-url": { type: "string" },
    "artifact-origin": { type: "string" },
    publisher: { type: "string" },
    "issued-at": { type: "string" },
    "expires-at": { type: "string" },
  },
});
const feature = values.feature;
const features = {
  indexing: {
    directory: "modules/indexing/native",
    command: "oc-indexing",
    permissions: ["indexing.manage"],
  },
  inventory: {
    directory: "modules/inventory/native",
    command: "oc-inventory",
    permissions: ["inventory.read"],
  },
  "windows-updates": {
    directory: "modules/windows-updates/native",
    command: "oc-windows-updates",
    permissions: ["windows.manage"],
  },
};
const definition = Object.hasOwn(features, feature ?? "") ? features[feature] : undefined;
if (!definition) throw new Error(`Select a supported optional feature: ${Object.keys(features).join(", ")}.`);
const platform = values.platform;
const architecture = { "win-x64": "amd64", "win-arm64": "arm64" }[platform];
if (!architecture) throw new Error("Select win-x64 or win-arm64.");
if (!/^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$/u.test(values.version ?? ""))
  throw new Error("An explicit module version is required.");
if (!/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/u.test(values.publisher ?? ""))
  throw new Error("An explicit publisher ID is required.");
if (!!values["artifact-url"] === !!values["artifact-origin"])
  throw new Error("Supply exactly one artifact-origin or artifact-url.");
const url = new URL(values["artifact-origin"] ?? values["artifact-url"]);
if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search)
  throw new Error("Supply an immutable HTTPS artifact URL without credentials or query parameters.");
if (values["artifact-origin"] && (url.pathname !== "/" || url.port))
  throw new Error("Artifact origin must use HTTPS on the default port with no path.");
const issuedAt = Number(values["issued-at"]),
  expiresAt = Number(values["expires-at"]);
if (
  !Number.isSafeInteger(issuedAt) ||
  !Number.isSafeInteger(expiresAt) ||
  issuedAt <= 0 ||
  expiresAt <= issuedAt
)
  throw new Error("Supply explicit issued-at and expires-at Unix seconds.");
if (!values.output) throw new Error("A new output directory is required.");
const output = resolve(values.output);
mkdirSync(output);
const toolchain = resolveGo();
const executable = join(output, "host.exe");
const build = spawnSync(
  toolchain.command,
  [
    "-C",
    definition.directory,
    "build",
    "-trimpath",
    "-buildvcs=false",
    "-ldflags=-s -w",
    "-o",
    executable,
    `./cmd/${definition.command}`,
  ],
  {
    cwd: repository,
    env: { ...toolchain.env, GOOS: "windows", GOARCH: architecture, CGO_ENABLED: "0" },
    encoding: "utf8",
    windowsHide: true,
    timeout: 300_000,
  },
);
if (build.status !== 0) throw new Error(build.stderr || build.error?.message || "Feature build failed.");
const bytes = readFileSync(executable);
const name = Buffer.from("bin/host.exe");
const checksum = crc32(bytes);
// The delivery owner deliberately accepts a small ZIP subset: no descriptors,
// extra fields, comments, external attributes, directory entries or ZIP64.
const local = Buffer.alloc(30);
local.writeUInt32LE(0x04034b50, 0);
local.writeUInt16LE(20, 4);
local.writeUInt32LE(checksum, 14);
local.writeUInt32LE(bytes.length, 18);
local.writeUInt32LE(bytes.length, 22);
local.writeUInt16LE(name.length, 26);
const central = Buffer.alloc(46);
central.writeUInt32LE(0x02014b50, 0);
central.writeUInt16LE(20, 4);
central.writeUInt16LE(20, 6);
central.writeUInt32LE(checksum, 16);
central.writeUInt32LE(bytes.length, 20);
central.writeUInt32LE(bytes.length, 24);
central.writeUInt16LE(name.length, 28);
const centralOffset = local.length + name.length + bytes.length;
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(1, 8);
end.writeUInt16LE(1, 10);
end.writeUInt32LE(central.length + name.length, 12);
end.writeUInt32LE(centralOffset, 16);
const archive = Buffer.concat([local, name, bytes, central, name, end]);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const archiveName = `${feature}-${values.version}-${platform}.zip`;
const archiveHash = hash(archive);
if (values["artifact-origin"]) url.pathname = `/v1/artifacts/${archiveHash}/package.zip`;
writeFileSync(join(output, archiveName), archive, { flag: "wx" });
const attestation = {
  schemaVersion: 1,
  id: feature,
  version: values.version,
  platform,
  publisher: values.publisher,
  layout: "native-host-v1",
  archiveSha256: archiveHash,
  archiveSize: archive.length,
  files: [{ path: "bin/host.exe", sha256: hash(bytes), size: bytes.length }],
  issuedAt,
  expiresAt,
};
const manifest = {
  schemaVersion: 1,
  id: feature,
  version: values.version,
  kind: "feature",
  minimumBootstrap: "0.1.0",
  permissions: definition.permissions,
  dependencies: {},
  artifacts: { [platform]: { url: url.href, sha256: archiveHash, size: archive.length } },
};
const save = (name, data) =>
  writeFileSync(join(output, name), `${JSON.stringify(data, null, 2)}\n`, { flag: "wx" });
save("publisher-request.json", attestation);
save("manifest.json", manifest);
save("build.json", {
  schemaVersion: 1,
  feature,
  platform,
  version: values.version,
  toolchain: toolchain.version,
  archive: archiveName,
  sha256: archiveHash,
  size: archive.length,
  signed: false,
});
process.stdout.write(`Built ${archiveName}. Publisher signing and catalog publication are separate steps.\n`);
