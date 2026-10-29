import type { Policy } from "@one-control/module-contracts";
import {
  type Command,
  commandContext,
  commandSchema,
  envelopeSchema,
  isMutation,
  type SignedEnvelope,
} from "@one-control/protocol";
import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";
import { reconcileDeviceJobs } from "../../../apps/control-plane/src/coordinator.js";
import type { Database, TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { audit } from "../../../apps/control-plane/src/routes/context.js";
import { ApiError, hash, verifyRelease } from "../../../apps/control-plane/src/security.js";

export const nativeJobSchema = [
  `CREATE TABLE native_job_admissions (
  job_id uuid PRIMARY KEY REFERENCES jobs(id), enrollment_id uuid NOT NULL REFERENCES native_enrollments(id),
  scope_id uuid NOT NULL REFERENCES management_scopes(id), module_id text NOT NULL,
  creator_issuer text NOT NULL,creator_subject text NOT NULL,approver_issuer text,approver_subject text,
  CHECK((approver_issuer IS NULL)=(approver_subject IS NULL))
 )`,
  `CREATE TABLE native_job_claims (
  id uuid PRIMARY KEY,job_id uuid NOT NULL UNIQUE REFERENCES jobs(id),enrollment_id uuid NOT NULL REFERENCES native_enrollments(id),
  credential_hash text NOT NULL,request_digest text NOT NULL,lease_hash text NOT NULL,response jsonb NOT NULL,
  state text NOT NULL CHECK(state IN ('issued','terminal','quarantined')),created_at timestamptz NOT NULL DEFAULT clock_timestamp()
 )`,
  `CREATE TABLE native_job_receipts (
  job_id uuid PRIMARY KEY REFERENCES jobs(id),claim_id uuid NOT NULL REFERENCES native_job_claims(id),
  digest text NOT NULL,outcome text NOT NULL CHECK(outcome IN ('succeeded','failed','indeterminate')),result jsonb NOT NULL,
  receipt jsonb NOT NULL,received_at timestamptz NOT NULL DEFAULT clock_timestamp()
 )`,
  `UPDATE jobs SET state=CASE WHEN state='leased' THEN 'indeterminate' ELSE 'cancelled' END,lease_hash=NULL,lease_expires_at=NULL,finished_at=clock_timestamp() WHERE state IN ('awaiting_approval','queued','leased')`,
] as const;
export const nativeClaimReconciliationSchema = [
  `ALTER TABLE native_job_claims ALTER COLUMN job_id DROP NOT NULL`,
  `ALTER TABLE native_job_claims DROP CONSTRAINT native_job_claims_state_check`,
  `ALTER TABLE native_job_claims ADD CONSTRAINT native_job_claims_state_check CHECK(state IN ('issued','empty','terminal','quarantined'))`,
  `ALTER TABLE native_job_claims ADD CONSTRAINT native_job_claims_empty_check CHECK((job_id IS NULL AND state IN ('empty','quarantined')) OR (job_id IS NOT NULL AND state<>'empty'))`,
] as const;
type Enrollment = { id: string; scope_id: string; device_id: string; platform: string; machine_id: string };
type Admission = {
  job_id: string;
  enrollment_id: string;
  scope_id: string;
  module_id: string;
  creator_issuer: string;
  creator_subject: string;
  approver_issuer: string | null;
  approver_subject: string | null;
};
type Job = {
  id: string;
  command: Command;
  state: string;
  ends_at: Date;
  lease_expires_at: Date | null;
  lease_hash: string | null;
};
export type NativeJobBoundary = {
  credential: (tx: TransactionQuery, credentialHash: string) => Promise<Enrollment>;
  policy: (
    tx: TransactionQuery,
    credentialHash: string,
    digest: string,
  ) => Promise<{ enrollment: Enrollment; policy: Policy }>;
  command: (
    tx: TransactionQuery,
    scope: string,
    command: Command,
    admission: Admission,
    policy: Policy,
  ) => Promise<void>;
};
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const token = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .refine((value) => Buffer.from(value, "base64url").toString("base64url") === value);
const leaseInput = z.strictObject({ claimId: z.uuid(), leaseToken: token, policyDigest: digest });
async function admission(tx: TransactionQuery, id: string, enrollment: Enrollment) {
  const [row] = await tx.query<Admission>(
    "SELECT * FROM native_job_admissions WHERE job_id=$1 AND enrollment_id=$2 AND scope_id=$3",
    [id, enrollment.id, enrollment.scope_id],
  );
  if (!row) throw new ApiError(409, "native_job_admission_missing");
  return row;
}
async function job(tx: TransactionQuery, id: string, enrollment: Enrollment) {
  const [row] = await tx.query<Job>(
    "SELECT id,command,state,ends_at,lease_expires_at,lease_hash FROM jobs WHERE id=$1 AND device_id=$2 FOR UPDATE",
    [id, enrollment.device_id],
  );
  if (!row) throw new ApiError(404, "job_not_found");
  return row;
}
export function nativeJobControl(db: Database, config: Config, boundary: NativeJobBoundary) {
  return {
    async readNativeClaim(credential: string, id: string) {
      z.uuid().parse(id);
      return db.transaction(async (tx) => {
        const enrollment = await boundary.credential(tx, hash(credential));
        const [claim] = await tx.query<{ state: string; response: unknown; receipt: unknown }>(
          `SELECT c.state,c.response,r.receipt FROM native_job_claims c
           LEFT JOIN native_job_receipts r ON r.claim_id=c.id
           WHERE c.id=$1 AND c.enrollment_id=$2`,
          [id, enrollment.id],
        );
        if (!claim) throw new ApiError(404, "native_claim_not_found");
        return { state: claim.state, response: claim.response, receipt: claim.receipt ?? null };
      });
    },
    async claimNativeJob(credential: string, raw: unknown) {
      const input = z
          .strictObject({ requestId: z.uuid(), leaseTokenHash: digest, policyDigest: digest })
          .parse(raw),
        credentialHash = hash(credential),
        requestDigest = hash(JSON.stringify(input));
      return db.transaction(async (tx) => {
        const { enrollment, policy } = await boundary.policy(tx, credentialHash, input.policyDigest);
        const [prior] = await tx.query<{
          job_id: string | null;
          enrollment_id: string;
          credential_hash: string;
          request_digest: string;
          state: string;
          response: unknown;
        }>(
          "SELECT job_id,enrollment_id,credential_hash,request_digest,state,response FROM native_job_claims WHERE id=$1",
          [input.requestId],
        );
        if (prior) {
          if (
            prior.enrollment_id !== enrollment.id ||
            prior.credential_hash !== credentialHash ||
            prior.request_digest !== requestDigest
          )
            throw new ApiError(409, "native_claim_conflict");
          if (prior.state === "empty" && prior.job_id === null) return prior.response;
          if (prior.job_id === null) throw new ApiError(409, "native_claim_unavailable");
          const current = await job(tx, prior.job_id, enrollment),
            binding = await admission(tx, current.id, enrollment);
          await boundary.command(tx, enrollment.scope_id, current.command, binding, policy);
          if (
            prior.state !== "issued" ||
            current.state !== "leased" ||
            !current.lease_expires_at ||
            new Date(current.lease_expires_at).getTime() <= Date.now()
          )
            throw new ApiError(409, "lease_lost");
          return prior.response;
        }
        const empty = async () => {
          const response = { lease: null };
          await tx.query(
            "INSERT INTO native_job_claims(id,job_id,enrollment_id,credential_hash,request_digest,lease_hash,response,state) VALUES($1,NULL,$2,$3,$4,$5,$6,'empty')",
            [
              input.requestId,
              enrollment.id,
              credentialHash,
              requestDigest,
              input.leaseTokenHash,
              JSON.stringify(response),
            ],
          );
          return response;
        };
        const [device] = await tx.query<{ ring: string }>("SELECT ring FROM devices WHERE id=$1", [
          enrollment.device_id,
        ]);
        if (config.DEPLOYMENT_STAGE === "poc" && device?.ring !== "canary") return empty();
        await reconcileDeviceJobs(tx, enrollment.device_id);
        if (
          (
            await tx.query(
              "SELECT id FROM jobs WHERE device_id=$1 AND state IN ('leased','indeterminate') LIMIT 1",
              [enrollment.device_id],
            )
          ).length
        )
          return empty();
        const [candidate] = await tx.query<{ id: string }>(
          "SELECT j.id FROM jobs j JOIN native_job_admissions a ON a.job_id=j.id WHERE j.device_id=$1 AND a.enrollment_id=$2 AND j.state='queued' AND j.starts_at<=clock_timestamp() AND j.ends_at>clock_timestamp() AND j.context='system' ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF j",
          [enrollment.device_id, enrollment.id],
        );
        if (!candidate) return empty();
        const current = await job(tx, candidate.id, enrollment),
          binding = await admission(tx, current.id, enrollment);
        current.command = commandSchema.parse(current.command);
        await boundary.command(tx, enrollment.scope_id, current.command, binding, policy);
        if (commandContext(current.command) !== "system")
          throw new ApiError(409, "native_user_session_required");
        let release: SignedEnvelope | null = null;
        if (current.command.kind === "package.install") {
          const [row] = await tx.query<{ envelope: unknown }>("SELECT envelope FROM releases WHERE id=$1", [
            current.command.releaseId,
          ]);
          if (!row) throw new ApiError(409, "release_not_found");
          release = envelopeSchema.parse(row.envelope);
          verifyRelease(release, config);
        }
        const [leased] = await tx.query<{ lease_expires_at: Date }>(
          "UPDATE jobs SET state='leased',attempt=attempt+1,lease_hash=$2,lease_expires_at=LEAST(clock_timestamp()+interval '120 seconds',ends_at,to_timestamp($3)) WHERE id=$1 AND state='queued' AND ends_at>clock_timestamp() AND clock_timestamp()<to_timestamp($3) AND EXISTS(SELECT 1 FROM credentials WHERE hash=$4 AND revoked_at IS NULL AND expires_at>clock_timestamp()) RETURNING lease_expires_at",
          [current.id, input.leaseTokenHash, policy.expiresAt, credentialHash],
        );
        if (!leased) throw new ApiError(409, "lease_lost");
        const response = {
          lease: {
            id: current.id,
            claimId: input.requestId,
            leaseExpiresAt: new Date(leased.lease_expires_at).toISOString(),
            endsAt: new Date(current.ends_at).toISOString(),
            command: current.command,
            release,
            moduleId: binding.module_id,
            moduleVersion: policy.enabled[binding.module_id],
            policyDigest: input.policyDigest,
            enrollmentId: enrollment.id,
          },
        };
        await tx.query(
          "INSERT INTO native_job_claims(id,job_id,enrollment_id,credential_hash,request_digest,lease_hash,response,state) VALUES($1,$2,$3,$4,$5,$6,$7,'issued')",
          [
            input.requestId,
            current.id,
            enrollment.id,
            credentialHash,
            requestDigest,
            input.leaseTokenHash,
            JSON.stringify(response),
          ],
        );
        await audit(tx, `device:${enrollment.device_id}`, "native.job_leased", current.id, {
          scope: enrollment.scope_id,
          enrollment: enrollment.id,
          claim: input.requestId,
        });
        return response;
      });
    },
    async renewNativeJob(credential: string, id: string, raw: unknown) {
      z.uuid().parse(id);
      const input = leaseInput.parse(raw);
      return db.transaction(async (tx) => {
        const { enrollment, policy } = await boundary.policy(tx, hash(credential), input.policyDigest),
          current = await job(tx, id, enrollment),
          binding = await admission(tx, id, enrollment);
        await boundary.command(tx, enrollment.scope_id, current.command, binding, policy);
        const [claim] = await tx.query(
          "SELECT id FROM native_job_claims WHERE id=$1 AND job_id=$2 AND enrollment_id=$3 AND lease_hash=$4 AND state='issued'",
          [input.claimId, id, enrollment.id, hash(input.leaseToken)],
        );
        if (!claim) throw new ApiError(409, "lease_lost");
        const [renewed] = await tx.query<{ lease_expires_at: Date }>(
          "UPDATE jobs SET lease_expires_at=LEAST(clock_timestamp()+interval '120 seconds',ends_at,to_timestamp($3)) WHERE id=$1 AND state='leased' AND lease_hash=$2 AND lease_expires_at>clock_timestamp() AND ends_at>clock_timestamp() AND clock_timestamp()<to_timestamp($3) AND EXISTS(SELECT 1 FROM credentials WHERE hash=$4 AND revoked_at IS NULL AND expires_at>clock_timestamp()) RETURNING lease_expires_at",
          [id, hash(input.leaseToken), policy.expiresAt, hash(credential)],
        );
        if (!renewed) throw new ApiError(409, "lease_lost");
        return { leaseExpiresAt: new Date(renewed.lease_expires_at).toISOString() };
      });
    },
    async reportNativeJob(credential: string, id: string, raw: unknown) {
      z.uuid().parse(id);
      const input = z
        .strictObject({
          claimId: z.uuid(),
          leaseToken: token,
          state: z.enum(["succeeded", "failed", "indeterminate"]),
          result: z.record(z.string(), z.json()),
        })
        .parse(raw);
      const resultDigest = hash(
        JSON.stringify({ claimId: input.claimId, state: input.state, result: input.result }),
      );
      return db.transaction(async (tx) => {
        // Terminal evidence remains admissible after module disable, never renewed execution authority.
        const enrollment = await boundary.credential(tx, hash(credential));
        const current = await job(tx, id, enrollment);
        const [claim] = await tx.query<{ state: string }>(
          "SELECT state FROM native_job_claims WHERE id=$1 AND job_id=$2 AND enrollment_id=$3 AND lease_hash=$4",
          [input.claimId, id, enrollment.id, hash(input.leaseToken)],
        );
        if (!claim || claim.state === "quarantined") throw new ApiError(409, "native_claim_unavailable");
        const [prior] = await tx.query<{ digest: string; receipt: unknown }>(
          "SELECT digest,receipt FROM native_job_receipts WHERE job_id=$1",
          [id],
        );
        if (prior) {
          if (prior.digest !== resultDigest) throw new ApiError(409, "native_terminal_conflict");
          return prior.receipt;
        }
        const updated = await tx.query(
          "UPDATE jobs SET state=$2,result=$3,lease_hash=NULL,lease_expires_at=NULL,finished_at=clock_timestamp() WHERE id=$1 AND state='leased' AND lease_hash=$4 AND lease_expires_at>clock_timestamp() AND ends_at>clock_timestamp() RETURNING id",
          [id, input.state, JSON.stringify(input.result), hash(input.leaseToken)],
        );
        if (!updated.length && current.state === "leased")
          await tx.query(
            "UPDATE jobs SET state='indeterminate',lease_hash=NULL,lease_expires_at=NULL,finished_at=clock_timestamp() WHERE id=$1",
            [id],
          );
        const receipt = {
          jobId: id,
          claimId: input.claimId,
          recordedOutcome: input.state,
          applied: updated.length === 1,
          requiresReconciliation: updated.length === 0,
        };
        await tx.query(
          "INSERT INTO native_job_receipts(job_id,claim_id,digest,outcome,result,receipt) VALUES($1,$2,$3,$4,$5,$6)",
          [
            id,
            input.claimId,
            resultDigest,
            input.state,
            JSON.stringify(input.result),
            JSON.stringify(receipt),
          ],
        );
        await tx.query("UPDATE native_job_claims SET state='terminal' WHERE id=$1", [input.claimId]);
        await audit(tx, `device:${enrollment.device_id}`, "native.job_reported", id, {
          scope: enrollment.scope_id,
          outcome: input.state,
          applied: receipt.applied,
        });
        return receipt;
      });
    },
  };
}

export function nativeCommandSelected(command: Command, admission: Admission, policy: Policy) {
  if (!policy.enabled[admission.module_id] || policy.disabled.includes(admission.module_id))
    throw new ApiError(403, "native_command_module_not_selected");
  if (
    isMutation(command) &&
    (!admission.approver_issuer ||
      !admission.approver_subject ||
      (admission.creator_issuer === admission.approver_issuer &&
        admission.creator_subject === admission.approver_subject))
  )
    throw new ApiError(403, "native_independent_approval_required");
}
