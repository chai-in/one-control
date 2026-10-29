import {
  type CatalogEntry,
  type ModuleCatalog,
  type PackageAttestation,
  parseWire,
} from "@one-control/module-contracts";
import { ApiError } from "../../../apps/control-plane/src/security.js";
import { type NativeAuthority, nativeDigest, type SignedNative } from "./signing.js";

function inventory(attestation: PackageAttestation) {
  if (
    attestation.files.length < 1 ||
    attestation.files.length > 128 ||
    attestation.archiveSize > 16 * 1024 * 1024
  )
    throw new ApiError(400, "native_package_limits");
  const seen = new Set<string>(),
    prefixes = new Map<string, string>();
  let total = 0,
    host = false;
  for (const file of attestation.files) {
    const parts = file.path.split("/");
    if (
      file.path.length > 240 ||
      parts.length > 8 ||
      parts.some(
        (part) =>
          !/^[a-zA-Z0-9._-]+$/.test(part) ||
          part === "." ||
          part === ".." ||
          part.endsWith(".") ||
          /^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(part),
      ) ||
      file.size > 16 * 1024 * 1024
    )
      throw new ApiError(400, "native_package_inventory_invalid");
    const lower = file.path.toLowerCase();
    if (seen.has(lower)) throw new ApiError(400, "native_package_path_collision");
    seen.add(lower);
    for (let length = 1; length <= parts.length; length++) {
      const path = parts.slice(0, length).join("/"),
        fold = path.toLowerCase();
      if (prefixes.has(fold) && prefixes.get(fold) !== path)
        throw new ApiError(400, "native_package_path_collision");
      prefixes.set(fold, path);
    }
    total += file.size;
    if (total > 32 * 1024 * 1024) throw new ApiError(400, "native_package_limits");
    const entry = attestation.platform.startsWith("win-") ? "bin/host.exe" : "bin/host";
    if (attestation.layout === "native-host-v1" && file.path === entry) host = true;
    else if (!file.path.startsWith("data/")) throw new ApiError(400, "native_package_layout_invalid");
  }
  for (const path of seen) {
    const parts = path.split("/");
    for (let index = 1; index < parts.length; index++)
      if (seen.has(parts.slice(0, index).join("/"))) throw new ApiError(400, "native_package_path_collision");
  }
  if (attestation.layout === "native-host-v1" && !host)
    throw new ApiError(400, "native_package_host_missing");
}
export type PublisherEvidence = SignedNative & { envelopeDigest: string; document: PackageAttestation };
export function admittedCatalog(
  authority: NativeAuthority,
  entries: unknown,
  rawEvidence: readonly string[],
  revision: string,
  now: number,
  expires: number,
) {
  const bytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      authorityEpoch: authority.epoch,
      revision,
      issuedAt: now,
      expiresAt: expires,
      entries,
    }),
  );
  const document = parseWire("ModuleCatalog", bytes);
  const evidence = new Map<string, PublisherEvidence>();
  for (const encoded of rawEvidence) {
    const raw = Buffer.from(encoded, "base64url");
    if (raw.toString("base64url") !== encoded) throw new ApiError(400, "invalid_native_encoding");
    const verified = authority.verify(raw, "publisher-attestation.v1", now);
    const attestation = parseWire("PackageAttestation", verified.payload);
    if (!authority.configuration.publishers[attestation.publisher]?.includes(verified.keyId))
      throw new ApiError(400, "native_publisher_not_authorized");
    if (
      attestation.issuedAt > now ||
      attestation.expiresAt <= now ||
      attestation.expiresAt < expires ||
      verified.keyExpiresAt < expires
    )
      throw new ApiError(400, "native_publisher_evidence_expired");
    inventory(attestation);
    const envelopeDigest = nativeDigest(raw);
    evidence.set(envelopeDigest, { ...verified, envelopeDigest, document: attestation });
  }
  const seen = new Map<string, CatalogEntry>(),
    used = new Set<string>();
  for (const entry of document.entries) {
    const manifest = entry.manifest,
      key = `${manifest.id}@${manifest.version}`;
    if (
      seen.has(key) ||
      !Object.keys(manifest.artifacts).length ||
      Object.keys(manifest.artifacts).length !== Object.keys(entry.platforms).length
    )
      throw new ApiError(400, "native_catalog_invalid");
    seen.set(key, entry);
    for (const [platform, artifact] of Object.entries(manifest.artifacts)) {
      const metadata = entry.platforms[platform];
      const proof = metadata ? evidence.get(metadata.attestationSha256) : undefined;
      if (!metadata || !proof) throw new ApiError(400, "native_publisher_evidence_missing");
      const attestation = proof.document;
      if (
        metadata.scope !== "machine" ||
        (manifest.kind === "shared"
          ? metadata.layout !== "passive-v1" || metadata.hostAbi !== "none"
          : metadata.layout !== "native-host-v1" || metadata.hostAbi !== "one-control-host-v1")
      )
        throw new ApiError(400, "native_catalog_host_shape_invalid");
      if (
        attestation.id !== manifest.id ||
        attestation.version !== manifest.version ||
        attestation.platform !== platform ||
        attestation.publisher !== metadata.publisher ||
        attestation.layout !== metadata.layout ||
        attestation.archiveSha256 !== artifact.sha256 ||
        attestation.archiveSize !== artifact.size
      )
        throw new ApiError(400, "native_publisher_binding_invalid");
      if (
        !authority.configuration.artifactOrigins.some(
          (origin) => new URL(origin).origin === new URL(artifact.url).origin,
        )
      )
        throw new ApiError(400, "native_artifact_origin_denied");
      used.add(proof.envelopeDigest);
    }
  }
  const visiting = new Set<string>(),
    visited = new Set<string>();
  function visit(key: string) {
    if (visiting.has(key)) throw new ApiError(400, "native_catalog_dependency_cycle");
    if (visited.has(key)) return;
    const entry = seen.get(key);
    if (!entry) throw new ApiError(400, "native_catalog_dependency_missing");
    visiting.add(key);
    for (const [id, version] of Object.entries(entry.manifest.dependencies)) {
      const dependency = `${id}@${version}`;
      if (seen.get(dependency)?.manifest.kind !== "shared")
        throw new ApiError(400, "native_catalog_dependency_not_shared");
      visit(dependency);
    }
    visiting.delete(key);
    visited.add(key);
  }
  for (const key of seen.keys()) visit(key);
  return {
    document: document as ModuleCatalog,
    payload: bytes,
    evidence: [...evidence.values()].filter((item) => used.has(item.envelopeDigest)),
  };
}
