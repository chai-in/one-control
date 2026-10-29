// SPDX-License-Identifier: GPL-3.0-only
// Scoped adaptation of TIBCON Sentry Falcon sync and webhook ingestion workflows.
import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";
import type { TransactionQuery } from "../../../apps/control-plane/src/database.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";
import { FalconInventory, type falconResource } from "../../falcon/server/inventory.js";

type Resource = z.infer<typeof falconResource>;
type SyncState = {
  generation: string;
  status: string;
  cursor: { offset?: number; after?: string } | null;
  filter: string | null;
  count: number;
};
export async function syncFalconPage(
  tx: TransactionQuery,
  config: Config,
  scope: string,
  resource: Resource,
  input: { restart?: boolean; filter?: string | undefined },
  signal: AbortSignal,
) {
  if (scope !== config.FALCON_MANAGEMENT_SCOPE) throw new ApiError(503, "integration_scope_unconfigured");
  const [prior] = await tx.query<SyncState>(
    "SELECT generation,status,cursor,filter,count FROM falcon_sync_state WHERE scope_id=$1 AND resource=$2",
    [scope, resource],
  );
  const fresh = input.restart || !prior || ["complete", "paused"].includes(prior.status);
  const generation = fresh ? randomUUID() : prior.generation;
  const filter = fresh ? input.filter : (prior.filter ?? undefined);
  const cursor = fresh ? {} : (prior.cursor ?? {});
  if (!fresh && input.filter !== undefined && input.filter !== filter)
    throw new ApiError(409, "restart_sync_to_change_filter");
  if (fresh)
    await tx.query(
      `INSERT INTO falcon_sync_state(scope_id,resource,generation,status,filter) VALUES($1,$2,$3,'running',$4)
    ON CONFLICT(scope_id,resource) DO UPDATE SET generation=EXCLUDED.generation,status='running',filter=EXCLUDED.filter,cursor=NULL,count=0,error_code=NULL,started_at=clock_timestamp(),updated_at=clock_timestamp(),completed_at=NULL`,
      [scope, resource, generation, filter ?? null],
    );
  let page: Awaited<ReturnType<FalconInventory["page"]>>;
  try {
    page = await new FalconInventory(config, signal).page(resource, {
      scopeId: scope,
      limit: 100,
      offset: cursor.offset ?? 0,
      after: cursor.after,
      filter,
    });
  } catch (error) {
    const code = error instanceof ApiError ? error.code : "falcon_unavailable";
    await tx.query(
      "UPDATE falcon_sync_state SET status='error',error_code=$3,updated_at=clock_timestamp(),next_due_at=clock_timestamp()+interval '1 minute' WHERE scope_id=$1 AND resource=$2",
      [scope, resource, code],
    );
    return { resource, status: "error", error: code, count: fresh ? 0 : prior.count };
  }
  for (const item of page.records) {
    const record = z.record(z.string(), z.unknown()).parse(item);
    const sourceId = z
      .string()
      .min(1)
      .parse(record.device_id ?? record.id ?? record.composite_id ?? record.incident_id);
    await tx.query(
      `INSERT INTO falcon_cached_records(scope_id,resource,source_id,generation,payload,observed_at) VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(scope_id,resource,source_id) DO UPDATE SET generation=EXCLUDED.generation,payload=EXCLUDED.payload,observed_at=EXCLUDED.observed_at,present=true`,
      [scope, resource, sourceId, generation, JSON.stringify(record), page.collectedAt],
    );
  }
  if (!page.next)
    await tx.query(
      "UPDATE falcon_cached_records SET present=false WHERE scope_id=$1 AND resource=$2 AND generation<>$3",
      [scope, resource, generation],
    );
  const [state] = await tx.query(
    `UPDATE falcon_sync_state SET status=$3,cursor=$4,count=count+$5,error_code=NULL,updated_at=clock_timestamp(),
    completed_at=CASE WHEN $3='complete' THEN clock_timestamp() ELSE NULL END,
    next_due_at=clock_timestamp()+($6::int * interval '1 second') WHERE scope_id=$1 AND resource=$2 RETURNING resource,status,count,updated_at,completed_at`,
    [
      scope,
      resource,
      page.next ? "running" : "complete",
      page.next ? JSON.stringify(page.next) : null,
      page.records.length,
      page.next ? 0 : (config.FALCON_SYNC_INTERVAL_SECONDS ?? 0),
    ],
  );
  return state;
}
