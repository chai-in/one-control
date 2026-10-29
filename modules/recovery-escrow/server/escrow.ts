// SPDX-License-Identifier: GPL-3.0-only
// Escrow/list/reveal semantics adapted from TIBCON Sentry; see docs/sentry-integration.json.
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";
import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";
import type { TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { audit } from "../../../apps/control-plane/src/routes/context.js";
import { type Actor, ApiError } from "../../../apps/control-plane/src/security.js";

const keyId = z.string().regex(/^[a-z][a-z0-9.-]{0,63}$/);
const password = z
  .string()
  .regex(/^\d{6}(?:-\d{6}){7}$/)
  .refine((value) => value.split("-").every((group) => Number(group) % 11 === 0 && Number(group) <= 720885));
export const recoveryKeyInput = z.strictObject({
  policyDigest: z.string().regex(/^[a-f0-9]{64}$/),
  volume: z.string().regex(/^[A-Z]:$/),
  protectorId: z.uuid().transform((value) => value.toLowerCase()),
  recoveryKey: password,
});
type Keyring = { activeKeyId: string; keys: Map<string, Buffer> };
const rings = new WeakMap<Config, Promise<Keyring>>();
async function keyring(config: Config) {
  const { RECOVERY_ESCROW_KEYRING_FILE: keyringFile, CREDENTIAL_ROOT: credentialDirectory } = config;
  if (!keyringFile || !credentialDirectory || !isAbsolute(credentialDirectory))
    throw new ApiError(503, "recovery_escrow_unconfigured");
  let ring = rings.get(config);
  if (!ring) {
    ring = (async () => {
      const input = z
        .strictObject({
          activeKeyId: keyId,
          keys: z
            .record(keyId, z.string())
            .refine((value) => Object.keys(value).length > 0 && Object.keys(value).length <= 32),
        })
        .parse(JSON.parse(await readFile(keyringFile, "utf8")));
      const root = await realpath(credentialDirectory),
        keys = new Map<string, Buffer>();
      for (const [id, path] of Object.entries(input.keys)) {
        if (!isAbsolute(path)) throw new Error("key location");
        const resolved = await realpath(path),
          fromRoot = relative(root, resolved);
        if (fromRoot.startsWith("..") || isAbsolute(fromRoot)) throw new Error("key location");
        const bytes = await readFile(resolved);
        if (bytes.length !== 32) throw new Error("key size");
        keys.set(id, bytes);
      }
      if (!keys.has(input.activeKeyId)) throw new Error("active key missing");
      return { activeKeyId: input.activeKeyId, keys };
    })().catch(() => {
      rings.delete(config);
      throw new ApiError(503, "recovery_escrow_unavailable");
    });
    rings.set(config, ring);
  }
  return ring;
}
export const recoveryEscrowSchema = [
  `ALTER TABLE scope_grants DROP CONSTRAINT scope_grants_permission_check`,
  `ALTER TABLE scope_grants ADD CONSTRAINT scope_grants_permission_check CHECK(permission IN ('owner','view','enroll','configure','approve','command','reveal'))`,
  `CREATE TABLE recovery_key_escrow (
  id uuid PRIMARY KEY,scope_id uuid NOT NULL REFERENCES management_scopes(id),device_id uuid NOT NULL REFERENCES devices(id),enrollment_id uuid NOT NULL REFERENCES native_enrollments(id),
  volume text NOT NULL,protector_id uuid NOT NULL,key_id text NOT NULL,nonce bytea NOT NULL,ciphertext bytea NOT NULL,tag bytea NOT NULL,fingerprint bytea NOT NULL,
  escrowed_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(enrollment_id,protector_id)
 )`,
  `CREATE INDEX recovery_key_scope ON recovery_key_escrow(scope_id,device_id,escrowed_at DESC)`,
] as const;
type EscrowRow = {
  id: string;
  scope_id: string;
  device_id: string;
  enrollment_id: string;
  volume: string;
  protector_id: string;
  key_id: string;
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
  fingerprint: Buffer;
};
const aad = (
  row: Pick<EscrowRow, "id" | "scope_id" | "device_id" | "enrollment_id" | "volume" | "protector_id">,
) =>
  Buffer.from(
    JSON.stringify([
      "one-control-recovery-v1",
      row.id,
      row.scope_id,
      row.device_id,
      row.enrollment_id,
      row.volume,
      row.protector_id,
    ]),
  );
function open(row: EscrowRow, ring: Keyring) {
  const key = ring.keys.get(row.key_id);
  if (!key) throw new ApiError(503, "recovery_escrow_key_unavailable");
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, row.nonce);
    decipher.setAAD(aad(row));
    decipher.setAuthTag(row.tag);
    return Buffer.concat([decipher.update(row.ciphertext), decipher.final()]);
  } catch {
    throw new ApiError(503, "recovery_escrow_integrity_failed");
  }
}
export async function saveRecoveryKey(
  tx: TransactionQuery,
  config: Config,
  enrollment: { id: string; scope_id: string; device_id: string },
  input: z.output<typeof recoveryKeyInput>,
) {
  const ring = await keyring(config);
  const [prior] = await tx.query<EscrowRow>(
    "SELECT * FROM recovery_key_escrow WHERE enrollment_id=$1 AND protector_id=$2",
    [enrollment.id, input.protectorId],
  );
  const plaintext = Buffer.from(input.recoveryKey);
  try {
    if (prior) {
      const previous = open(prior, ring);
      try {
        if (
          prior.volume !== input.volume ||
          previous.length !== plaintext.length ||
          !timingSafeEqual(previous, plaintext)
        )
          throw new ApiError(409, "recovery_key_conflict");
      } finally {
        previous.fill(0);
      }
      return { id: prior.id, stored: true };
    }
    const row = {
      id: randomUUID(),
      scope_id: enrollment.scope_id,
      device_id: enrollment.device_id,
      enrollment_id: enrollment.id,
      volume: input.volume,
      protector_id: input.protectorId,
    };
    const key = ring.keys.get(ring.activeKeyId)!,
      nonce = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad(row));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const fingerprint = createHmac("sha256", key)
      .update("one-control-recovery-fingerprint-v1\n")
      .update(plaintext)
      .digest();
    await tx.query(
      "INSERT INTO recovery_key_escrow(id,scope_id,device_id,enrollment_id,volume,protector_id,key_id,nonce,ciphertext,tag,fingerprint) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
      [
        row.id,
        row.scope_id,
        row.device_id,
        row.enrollment_id,
        row.volume,
        row.protector_id,
        ring.activeKeyId,
        nonce,
        ciphertext,
        cipher.getAuthTag(),
        fingerprint,
      ],
    );
    await audit(tx, `device:${enrollment.device_id}`, "native.recovery_key_escrowed", row.id, {
      scope: enrollment.scope_id,
      enrollment: enrollment.id,
      protectorId: input.protectorId,
    });
    return { id: row.id, stored: true };
  } finally {
    plaintext.fill(0);
  }
}
export async function recoveryKeyMetadata(tx: TransactionQuery, scope: string, version: string) {
  return {
    version,
    keys: await tx.query(
      "SELECT k.id,k.device_id,k.enrollment_id,d.hostname,k.volume,k.protector_id,k.escrowed_at,e.revoked_at AS enrollment_revoked_at FROM recovery_key_escrow k JOIN devices d ON d.id=k.device_id JOIN native_enrollments e ON e.id=k.enrollment_id WHERE k.scope_id=$1 ORDER BY k.escrowed_at DESC,k.id LIMIT 1000",
      [scope],
    ),
  };
}
export const revealInput = z.strictObject({
  reason: z.enum(["device-recovery", "key-verification", "incident-response"]),
});
export function requireRecoveryStepUp(actor: Actor, config: Config) {
  const now = Math.floor(Date.now() / 1000),
    allowed = config.OIDC_STEP_UP_ACRS?.split(",").filter(Boolean) ?? [];
  if (
    !actor.authenticationTime ||
    actor.authenticationTime > now ||
    now - actor.authenticationTime > 300 ||
    (!actor.authenticationMethods?.includes("mfa") &&
      (!actor.authenticationContext || !allowed.includes(actor.authenticationContext)))
  )
    throw new ApiError(403, "recent_multifactor_authentication_required");
}
export async function revealRecoveryKey(
  tx: TransactionQuery,
  config: Config,
  scope: string,
  id: string,
  actor: Actor,
  reason: string,
) {
  const [row] = await tx.query<EscrowRow>("SELECT * FROM recovery_key_escrow WHERE scope_id=$1 AND id=$2", [
    scope,
    id,
  ]);
  if (!row) throw new ApiError(404, "recovery_key_not_found");
  const plaintext = open(row, await keyring(config));
  try {
    requireRecoveryStepUp(actor, config);
    await audit(tx, JSON.stringify([actor.issuer, actor.id]), "native.recovery_key_revealed", id, {
      scope,
      device: row.device_id,
      reason,
    });
    return { id, volume: row.volume, protectorId: row.protector_id, recoveryKey: plaintext.toString("utf8") };
  } finally {
    plaintext.fill(0);
  }
}
