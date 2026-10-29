import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { issueNativePackageReadUrl } from "../../../apps/artifacts/src/policy.js";
import type { Config } from "../../../apps/control-plane/src/config.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";

const secrets = new WeakMap<Config, Promise<string>>();
export async function artifactReadKey(config: Config) {
  const { CREDENTIAL_ROOT: root, ARTIFACT_READ_KEY_FILE: file } = config;
  if (!root || !file || !isAbsolute(root) || !isAbsolute(file))
    throw new ApiError(503, "native_artifact_service_unconfigured");
  let secret = secrets.get(config);
  if (!secret) {
    secret = (async () => {
      const base = await realpath(root),
        target = await realpath(file),
        child = relative(base, target);
      if (child.startsWith("..") || isAbsolute(child)) throw new Error("key outside credential root");
      const bytes = await readFile(target);
      if (bytes.length !== 32) throw new Error("invalid artifact key size");
      return bytes.toString("base64url");
    })().catch(() => {
      secrets.delete(config);
      throw new ApiError(503, "native_artifact_service_unavailable");
    });
    secrets.set(config, secret);
  }
  return secret;
}
export async function artifactTicket(
  artifact: { url: string; sha256: string; size: number },
  secret: string,
  expires: number,
  now: number,
) {
  const canonical = new URL(artifact.url);
  if (canonical.search || canonical.pathname !== `/v1/artifacts/${artifact.sha256}/package.zip`)
    throw new ApiError(409, "native_artifact_address_invalid");
  const url = await issueNativePackageReadUrl(
    { origin: canonical.origin, sha256: artifact.sha256, size: artifact.size, expires },
    secret,
    now,
  );
  return {
    url,
    sha256: artifact.sha256,
    size: artifact.size,
    expiresAt: new Date(expires * 1000).toISOString(),
  };
}
