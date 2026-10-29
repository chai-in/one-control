import { falconEventSchema } from "../../falcon-events/server/schema.js";

const falconSyncSchema = [
  "CREATE TABLE falcon_sync_state (\n    scope_id uuid NOT NULL REFERENCES management_scopes(id), resource text NOT NULL,\n    generation uuid NOT NULL, status text NOT NULL CHECK(status IN ('running','complete','error','paused')),\n    cursor jsonb, filter text, count int NOT NULL DEFAULT 0, error_code text,\n    started_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,\n    next_due_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(scope_id,resource)\n  )",
  "CREATE TABLE falcon_cached_records (\n    scope_id uuid NOT NULL REFERENCES management_scopes(id), resource text NOT NULL, source_id text NOT NULL,\n    generation uuid NOT NULL, payload jsonb NOT NULL, observed_at timestamptz NOT NULL,\n    present boolean NOT NULL DEFAULT true, PRIMARY KEY(scope_id,resource,source_id)\n  )",
] as const;
export const falconDataSchema = [...falconSyncSchema, ...falconEventSchema] as const;
