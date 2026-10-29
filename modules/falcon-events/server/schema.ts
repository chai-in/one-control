export const falconEventSchema = [
  "CREATE TABLE falcon_events (\n    scope_id uuid NOT NULL REFERENCES management_scopes(id), event_id text NOT NULL,\n    body_sha256 text NOT NULL, event_type text NOT NULL, aid text, payload jsonb NOT NULL,\n    occurred_at timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),\n    PRIMARY KEY(scope_id,event_id)\n  )",
  "CREATE INDEX falcon_events_time ON falcon_events(scope_id,occurred_at DESC,event_id)",
] as const;
