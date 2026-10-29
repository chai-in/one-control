export const MAXIMUM_LIFETIME_SECONDS = 24 * 60 * 60;
export const MAXIMUM_ARTIFACT_BYTES = 2_147_483_648;
export const MAXIMUM_NATIVE_PACKAGE_BYTES = 64 * 1024 * 1024;
const tokenPattern = /^[A-Za-z0-9_-]{43}$/;
const hostPattern =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const artifactPattern =
  /^\/v1\/artifacts\/([a-f0-9]{64})\/one-control-agent-(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,4})\.msi$/;
const nativePackagePattern = /^\/v1\/artifacts\/([a-f0-9]{64})\/package\.zip$/;

interface ParsedArtifact {
  kind: "agent-msi" | "native-package";
  key: string;
  filename: string;
  sha256: string;
  contentType: "application/octet-stream" | "application/zip";
  maximumSize: number;
}

function encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}
function decode(value: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== "string" || !tokenPattern.test(value)) return null;
  const bytes = Uint8Array.from(atob(`${value.replaceAll("-", "+").replaceAll("_", "/")}=`), (char) =>
    char.charCodeAt(0),
  );
  return bytes.length === 32 && encode(bytes) === value ? bytes : null;
}
function artifact(path: string): ParsedArtifact | null {
  const native = nativePackagePattern.exec(path);
  if (native?.[1])
    return {
      kind: "native-package",
      key: `artifacts/${native[1]}/package.zip`,
      filename: "package.zip",
      sha256: native[1],
      contentType: "application/zip",
      maximumSize: MAXIMUM_NATIVE_PACKAGE_BYTES,
    };
  const match = artifactPattern.exec(path);
  const sha256 = match?.[1];
  if (!match || !sha256 || Number(match[2]) > 255 || Number(match[3]) > 255 || Number(match[4]) > 65535)
    return null;
  const filename = path.slice(path.lastIndexOf("/") + 1);
  return {
    kind: "agent-msi",
    key: `artifacts/${sha256}/${filename}`,
    filename,
    sha256,
    contentType: "application/octet-stream",
    maximumSize: MAXIMUM_ARTIFACT_BYTES,
  };
}
function payload(url: URL, expires: string, size: string): Uint8Array<ArrayBuffer> {
  // GET and HEAD authorize the same read; the host, object, expiry and full byte size are bound.
  return new TextEncoder().encode(
    `one-control-artifact-read-v1\n${url.hostname}\n${url.pathname}\n${expires}\n${size}`,
  );
}
async function importKey(secret: unknown): Promise<CryptoKey> {
  const bytes = decode(secret);
  if (!bytes) throw new Error("A canonical 256-bit artifact read key is required");
  return crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
function origin(url: URL, host: string): boolean {
  return (
    hostPattern.test(host) &&
    url.protocol === "https:" &&
    !url.port &&
    !url.username &&
    !url.password &&
    !url.hash &&
    url.hostname === host
  );
}

export interface ArtifactRead extends ParsedArtifact {
  size: number;
  expires: number;
}

export async function authorizeRead(
  request: Request,
  host: string,
  secret: string,
  now: number,
  nativePackagesEnabled = false,
): Promise<ArtifactRead | null> {
  if (!["GET", "HEAD"].includes(request.method) || !decode(secret) || !Number.isSafeInteger(now)) return null;
  const url = new URL(request.url);
  const object = artifact(url.pathname);
  if (
    !object ||
    (object.kind === "native-package" && !nativePackagesEnabled) ||
    !origin(url, host) ||
    url.searchParams.size !== 3 ||
    !["e", "n", "s"].every((name) => url.searchParams.getAll(name).length === 1)
  )
    return null;
  const e = url.searchParams.get("e");
  const n = url.searchParams.get("n");
  if (!e || !n || !/^[1-9]\d{0,10}$/.test(e) || !/^[1-9]\d{0,9}$/.test(n)) return null;
  const expires = Number(e);
  const size = Number(n);
  const seconds = Math.floor(now / 1000);
  if (
    !Number.isSafeInteger(expires) ||
    expires <= seconds ||
    expires - seconds > MAXIMUM_LIFETIME_SECONDS ||
    !Number.isSafeInteger(size) ||
    size > object.maximumSize
  )
    return null;
  const signature = decode(url.searchParams.get("s"));
  if (
    !signature ||
    !(await crypto.subtle.verify("HMAC", await importKey(secret), signature, payload(url, e, n)))
  )
    return null;
  return { ...object, size, expires };
}

export async function issueReadUrl(
  input: { origin: string; sha256: string; version: string; size: number; expires: number },
  secret: string,
  now: number,
): Promise<string> {
  const path = `/v1/artifacts/${input.sha256}/one-control-agent-${input.version}.msi`;
  const object = artifact(path);
  if (object?.kind !== "agent-msi")
    throw new Error("Only an exact versioned, content-addressed agent MSI is permitted");
  return issue(input, path, object, secret, now);
}

export async function issueNativePackageReadUrl(
  input: { origin: string; sha256: string; size: number; expires: number },
  secret: string,
  now: number,
): Promise<string> {
  const path = `/v1/artifacts/${input.sha256}/package.zip`;
  const object = artifact(path);
  if (object?.kind !== "native-package")
    throw new Error("Only an exact content-addressed native package ZIP is permitted");
  return issue(input, path, object, secret, now);
}

async function issue(
  input: { origin: string; size: number; expires: number },
  path: string,
  object: ParsedArtifact,
  secret: string,
  now: number,
): Promise<string> {
  const url = new URL(input.origin);
  if (
    !origin(url, url.hostname) ||
    url.pathname !== "/" ||
    url.search ||
    !Number.isSafeInteger(input.size) ||
    input.size < 1 ||
    input.size > object.maximumSize ||
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(input.expires) ||
    input.expires <= Math.floor(now / 1000) ||
    input.expires - Math.floor(now / 1000) > MAXIMUM_LIFETIME_SECONDS
  )
    throw new Error("Invalid artifact read authorization");
  url.pathname = path;
  const e = String(input.expires);
  const n = String(input.size);
  url.searchParams.set("e", e);
  url.searchParams.set("n", n);
  url.searchParams.set(
    "s",
    encode(new Uint8Array(await crypto.subtle.sign("HMAC", await importKey(secret), payload(url, e, n)))),
  );
  return url.href;
}
