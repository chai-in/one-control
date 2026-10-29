import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
  sign,
  verify,
} from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { type Protected, parseWire } from "@one-control/module-contracts";
import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";

export const nativeRoles = {
  catalog: "module-catalog.v2",
  policy: "device-policy.v1",
  freshness: "policy-freshness.v1",
} as const;
export type NativeRole = keyof typeof nativeRoles;
const id = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/)
  .max(96);
const decimal = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const publicKeySchema = z.strictObject({
  id,
  role: z.enum(["module-catalog.v2", "device-policy.v1", "policy-freshness.v1", "publisher-attestation.v1"]),
  pem: z.string().min(1).max(12000),
  notBefore: z.number().int().positive(),
  notAfter: z.number().int().positive(),
});
const custodySchema = z.strictObject({
  custodyReference: z.string().min(1).max(255),
  rootVersion: decimal,
  authorityEpoch: decimal,
  administrators: z
    .array(z.strictObject({ issuer: z.string().min(1).max(2048), subject: z.string().min(1).max(255) }))
    .min(1)
    .max(32),
  keys: z.array(publicKeySchema).min(3).max(32),
  signers: z.strictObject({
    catalog: z.strictObject({ keyId: id, privateKeyFile: z.string() }),
    policy: z.strictObject({ keyId: id, privateKeyFile: z.string() }),
    freshness: z.strictObject({ keyId: id, privateKeyFile: z.string() }),
  }),
  publishers: z.record(id, z.array(id).min(1).max(16)),
  artifactOrigins: z
    .array(
      z.url().refine((value) => {
        const url = new URL(value);
        return (
          url.protocol === "https:" &&
          !url.username &&
          !url.password &&
          url.pathname === "/" &&
          !url.search &&
          !url.hash
        );
      }),
    )
    .min(1)
    .max(32),
});
export const nativeDigest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
export function nativeSigningBytes(keyId: string, protectedBytes: Buffer, payload: Buffer) {
  const parts: Buffer[] = [Buffer.from("ONECONTROL-SIGNED-V1\n")];
  for (const part of [Buffer.from(keyId), protectedBytes, payload]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(part.length);
    parts.push(length, part);
  }
  return Buffer.concat(parts);
}
function decode64(value: string, limit: number) {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length > limit || bytes.toString("base64url") !== value)
    throw new ApiError(400, "invalid_native_encoding");
  return bytes;
}
type Key = z.output<typeof publicKeySchema> & { publicKey: KeyObject };
export type SignedNative = {
  protectedBytes: Buffer;
  payload: Buffer;
  envelope: Buffer;
  digest: string;
  keyId: string;
  keyExpiresAt: number;
};
export class NativeAuthority {
  private readonly keys = new Map<string, Key>();
  private constructor(
    readonly configuration: z.output<typeof custodySchema>,
    private readonly signers: Record<NativeRole, KeyObject>,
  ) {
    const moduli = new Set<string>();
    for (const key of configuration.keys) {
      const publicKey = createPublicKey(key.pem);
      const jwk = publicKey.export({ format: "jwk" });
      const bits = publicKey.asymmetricKeyDetails?.modulusLength ?? 0;
      if (
        publicKey.asymmetricKeyType !== "rsa" ||
        bits < 3072 ||
        bits > 8192 ||
        jwk.e !== "AQAB" ||
        !jwk.n ||
        moduli.has(jwk.n) ||
        this.keys.has(key.id) ||
        key.notAfter <= key.notBefore
      )
        throw new ApiError(503, "native_trust_invalid");
      moduli.add(jwk.n);
      this.keys.set(key.id, { ...key, publicKey });
    }
    for (const role of Object.keys(nativeRoles) as NativeRole[]) {
      const key = this.keys.get(configuration.signers[role].keyId);
      if (
        !key ||
        key.role !== nativeRoles[role] ||
        createPublicKey(signers[role]).export({ format: "jwk" }).n !==
          key.publicKey.export({ format: "jwk" }).n
      )
        throw new ApiError(503, "native_signer_role_invalid");
    }
    for (const keys of Object.values(configuration.publishers))
      for (const key of keys)
        if (this.keys.get(key)?.role !== "publisher-attestation.v1")
          throw new ApiError(503, "native_publisher_trust_invalid");
  }
  static async open(path: string, credentialDirectory: string) {
    if (!isAbsolute(path)) throw new ApiError(503, "native_custody_path_invalid");
    const configuration = custodySchema.parse(JSON.parse(await readFile(path, "utf8")));
    const loaded = {} as Record<NativeRole, KeyObject>;
    if (!isAbsolute(credentialDirectory)) throw new ApiError(503, "native_key_storage_invalid");
    const credentialRoot = await realpath(credentialDirectory);
    for (const role of Object.keys(nativeRoles) as NativeRole[]) {
      const path = configuration.signers[role].privateKeyFile;
      if (!isAbsolute(path)) throw new ApiError(503, "native_key_storage_invalid");
      const resolvedPath = await realpath(path);
      const fromRoot = relative(credentialRoot, resolvedPath);
      if (fromRoot.startsWith("..") || isAbsolute(fromRoot))
        throw new ApiError(503, "native_key_storage_invalid");
      loaded[role] = createPrivateKey(await readFile(resolvedPath));
    }
    return new NativeAuthority(configuration, loaded);
  }
  get reference() {
    return this.configuration.custodyReference;
  }
  get rootVersion() {
    return this.configuration.rootVersion;
  }
  get epoch() {
    return this.configuration.authorityEpoch;
  }
  publicTrust() {
    return {
      rootVersion: this.rootVersion,
      authorityEpoch: this.epoch,
      keys: this.configuration.keys,
      publishers: this.configuration.publishers,
      artifactOrigins: this.configuration.artifactOrigins,
    };
  }
  expires(role: NativeRole) {
    return this.keys.get(this.configuration.signers[role].keyId)!.notAfter;
  }
  header(role: NativeRole): Buffer {
    const value: Protected = {
      schemaVersion: 1,
      domain: nativeRoles[role],
      alg: "PS256",
      rootVersion: this.rootVersion,
      keyId: this.configuration.signers[role].keyId,
    };
    const bytes = Buffer.from(JSON.stringify(value));
    parseWire("Protected", bytes);
    return bytes;
  }
  verify(envelope: Buffer, role: string, now: number): SignedNative {
    const value = parseWire("Envelope", envelope);
    const protectedBytes = decode64(value.protected, 4096),
      payload = decode64(value.payload, 4194304),
      signature = decode64(value.signature, 1024);
    const header = parseWire("Protected", protectedBytes);
    const key = this.keys.get(header.keyId);
    if (header.domain !== role || header.rootVersion !== this.rootVersion || !key || key.role !== role)
      throw new ApiError(400, "native_signature_role_or_root_invalid");
    if (now < key.notBefore || now >= key.notAfter) throw new ApiError(400, "native_signing_key_expired");
    if (
      !verify(
        "sha256",
        nativeSigningBytes(header.keyId, protectedBytes, payload),
        { key: key.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        signature,
      )
    )
      throw new ApiError(400, "native_signature_invalid");
    return {
      protectedBytes,
      payload,
      envelope,
      digest: nativeDigest(payload),
      keyId: header.keyId,
      keyExpiresAt: key.notAfter,
    };
  }
  async sign(
    role: NativeRole,
    protectedBytes: Buffer,
    payload: Buffer,
    signal: AbortSignal,
  ): Promise<SignedNative> {
    const header = parseWire("Protected", protectedBytes);
    if (!protectedBytes.equals(this.header(role))) throw new ApiError(503, "native_signing_intent_mismatch");
    signal.throwIfAborted();
    const signature = await new Promise<Buffer>((resolve, reject) => {
      const aborted = () => reject(new ApiError(503, "native_signer_deadline"));
      signal.addEventListener("abort", aborted, { once: true });
      sign(
        "sha256",
        nativeSigningBytes(header.keyId, protectedBytes, payload),
        { key: this.signers[role], padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        (error, result) => {
          signal.removeEventListener("abort", aborted);
          if (error) reject(new ApiError(503, "native_signer_unavailable"));
          else resolve(result);
        },
      );
    });
    signal.throwIfAborted();
    const envelope = Buffer.from(
      JSON.stringify({
        protected: protectedBytes.toString("base64url"),
        payload: payload.toString("base64url"),
        signature: signature.toString("base64url"),
      }),
    );
    return this.verify(envelope, nativeRoles[role], Math.floor(Date.now() / 1000));
  }
}
const authorities = new WeakMap<Config, Promise<NativeAuthority>>();
export function nativeAuthority(config: Config): Promise<NativeAuthority> {
  if (!config.NATIVE_AUTHORITY_CONFIG || !config.CREDENTIAL_ROOT)
    throw new ApiError(503, "native_custody_unconfigured");
  let authority = authorities.get(config);
  if (!authority) {
    authority = NativeAuthority.open(config.NATIVE_AUTHORITY_CONFIG, config.CREDENTIAL_ROOT).catch(() => {
      authorities.delete(config);
      throw new ApiError(503, "native_custody_unavailable");
    });
    authorities.set(config, authority);
  }
  return authority;
}
