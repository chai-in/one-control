import type { TransactionQuery } from "./database.js";
import type { Actor } from "./security.js";

/** Resolve every affected scope before exposing an event, including multi-scope batches. */
export async function readAuditHistory(
  db: TransactionQuery,
  actor: Actor,
  after: number,
  direction: "forward" | "latest",
  scopeId?: string,
) {
  return db.query(
    `SELECT a.sequence,a.actor,a.action,a.subject,a.detail,a.created_at
    FROM audit_events a
    CROSS JOIN LATERAL (
      SELECT array_agg(DISTINCT related.scope_id) AS ids FROM (
        SELECT s.id AS scope_id FROM management_scopes s
          WHERE s.id::text=a.subject OR s.id::text=a.detail->>'scope'
        UNION ALL
        SELECT e.scope_id FROM native_enrollments e
          WHERE e.id::text=a.subject OR e.device_id::text=a.subject
        UNION ALL
        SELECT e.scope_id FROM jobs j JOIN native_enrollments e ON e.device_id=j.device_id
          WHERE j.id::text=a.subject OR j.batch_id::text=a.subject
      ) related
    ) scopes
    WHERE a.sequence>$1
      AND ($4::uuid IS NULL OR $4::uuid=ANY(scopes.ids))
      AND (
        (scopes.ids IS NULL AND a.action NOT LIKE 'scope.%' AND a.action NOT LIKE 'native.%')
        OR (scopes.ids IS NOT NULL AND NOT EXISTS (
          SELECT 1 FROM unnest(scopes.ids) affected(id)
          WHERE NOT EXISTS (
            SELECT 1 FROM management_scopes s JOIN scope_grants g ON g.scope_id=s.id
            WHERE s.id=affected.id AND s.state='active' AND g.issuer=$2 AND g.subject=$3
              AND g.permission IN ('owner','view') AND g.revoked_at IS NULL
          )
        ))
      )
    ORDER BY a.sequence ${direction === "latest" ? "DESC" : "ASC"} LIMIT 500`,
    [after, actor.issuer, actor.id, scopeId ?? null],
  );
}
