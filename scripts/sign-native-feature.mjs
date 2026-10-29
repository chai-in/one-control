import { constants, createHash, createPrivateKey, sign } from "node:crypto";
import { readFile, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { parseWire } from "../packages/module-contracts/src/validate.mjs";

const { values } = parseArgs({ options: { build: { type: "string" }, custody: { type: "string" } } });
if (!values.build || !values.custody || !isAbsolute(values.custody))
  throw new Error("Supply a build directory and absolute private publisher custody file");
const directory = resolve(values.build);
const custody = JSON.parse(await readFile(values.custody, "utf8"));
if (!isAbsolute(custody.credentialRoot) || !isAbsolute(custody.privateKeyFile))
  throw new Error("Explicit publisher credential custody is required");
const root = await realpath(custody.credentialRoot);
const keyFile = await realpath(custody.privateKeyFile);
const child = relative(root, keyFile);
if (child.startsWith("..") || isAbsolute(child)) throw new Error("Publisher key is outside custody");
const request = JSON.parse(await readFile(join(directory, "publisher-request.json"), "utf8"));
const payload = Buffer.from(JSON.stringify(request));
parseWire("PackageAttestation", payload);
if (request.publisher !== custody.publisher || request.expiresAt <= Math.floor(Date.now() / 1000))
  throw new Error("Publisher request does not match current custody");
const manifest = JSON.parse(await readFile(join(directory, "manifest.json"), "utf8"));
const build = JSON.parse(await readFile(join(directory, "build.json"), "utf8"));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
if (!/^[a-z0-9.-]+\.zip$/.test(build.archive)) throw new Error("Invalid build archive name");
const archive = await readFile(join(directory, build.archive));
const executable = await readFile(join(directory, "host.exe"));
const artifact = manifest.artifacts?.[request.platform];
if (
  manifest.id !== request.id ||
  manifest.version !== request.version ||
  manifest.kind !== "feature" ||
  request.archiveSha256 !== sha(archive) ||
  request.archiveSize !== archive.length ||
  request.files.length !== 1 ||
  request.files[0].path !== "bin/host.exe" ||
  request.files[0].sha256 !== sha(executable) ||
  request.files[0].size !== executable.length ||
  artifact?.sha256 !== request.archiveSha256 ||
  artifact?.size !== archive.length
)
  throw new Error("Build bytes do not match the publisher request");
const keyBytes = await readFile(keyFile);
let key;
try {
  key = createPrivateKey(keyBytes);
} finally {
  keyBytes.fill(0);
}
if (
  key.asymmetricKeyType !== "rsa" ||
  key.asymmetricKeyDetails.modulusLength < 3072 ||
  key.asymmetricKeyDetails.modulusLength > 8192 ||
  key.asymmetricKeyDetails.publicExponent !== 65537n
)
  throw new Error("Publisher requires RSA 3072-8192 with exponent 65537");
const protectedBytes = Buffer.from(
  JSON.stringify({
    schemaVersion: 1,
    domain: "publisher-attestation.v1",
    alg: "PS256",
    rootVersion: custody.rootVersion,
    keyId: custody.keyId,
  }),
);
parseWire("Protected", protectedBytes);
const parts = [Buffer.from("ONECONTROL-SIGNED-V1\n")];
for (const part of [Buffer.from(custody.keyId), protectedBytes, payload]) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(part.length);
  parts.push(length, part);
}
const signature = sign("sha256", Buffer.concat(parts), {
  key,
  padding: constants.RSA_PKCS1_PSS_PADDING,
  saltLength: 32,
});
const envelope = Buffer.from(
  JSON.stringify({
    protected: protectedBytes.toString("base64url"),
    payload: payload.toString("base64url"),
    signature: signature.toString("base64url"),
  }),
);
const publication = {
  entry: {
    manifest,
    platforms: {
      [request.platform]: {
        publisher: request.publisher,
        layout: "native-host-v1",
        hostAbi: "one-control-host-v1",
        scope: "machine",
        attestationSha256: sha(envelope),
      },
    },
  },
  attestation: envelope.toString("base64url"),
};
await writeFile(join(directory, "signed-module.json"), `${JSON.stringify(publication, null, 2)}\n`, {
  flag: "wx",
});
process.stdout.write(
  `Signed ${request.id}@${request.version} for ${request.platform}. Catalog admission and endpoint selection remain separate.\n`,
);
