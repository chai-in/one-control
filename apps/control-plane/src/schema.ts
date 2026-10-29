export const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE devices (
  id uuid PRIMARY KEY, hostname text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 255),
  ring text NOT NULL DEFAULT 'canary' CHECK (ring IN ('canary','pilot','broad')),
  last_seen_at timestamptz, inventory jsonb, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE enrollment_tokens (
  hash text PRIMARY KEY, context text NOT NULL CHECK (context IN ('system','user')),
  device_id uuid REFERENCES devices(id), expires_at timestamptz NOT NULL,
  used_at timestamptz, created_by text NOT NULL,
  CHECK (context = 'system' OR device_id IS NOT NULL)
);
CREATE TABLE credentials (
  hash text PRIMARY KEY, device_id uuid NOT NULL REFERENCES devices(id),
  context text NOT NULL CHECK (context IN ('system','user')),
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE TABLE releases (
  id uuid PRIMARY KEY, package_id text NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),
  envelope jsonb NOT NULL, manifest jsonb NOT NULL, created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(package_id, sequence)
);
CREATE TABLE batches (
  id uuid PRIMARY KEY, created_by text NOT NULL, approved_by text, command jsonb NOT NULL,
  ring text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE jobs (
  id uuid PRIMARY KEY, batch_id uuid NOT NULL REFERENCES batches(id),
  device_id uuid NOT NULL REFERENCES devices(id), context text NOT NULL,
  kind text NOT NULL, command jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('awaiting_approval','queued','leased','succeeded','failed','cancelled','indeterminate')),
  starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
  lease_hash text, lease_expires_at timestamptz, attempt int NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),
  result jsonb, created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
  UNIQUE(batch_id, device_id),
  CHECK ((state = 'leased') = (lease_hash IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX jobs_dispatch ON jobs(device_id, context, state, starts_at);
CREATE UNIQUE INDEX one_lease_per_device ON jobs(device_id) WHERE state = 'leased';
CREATE TABLE audit_events (
  sequence bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL, subject text NOT NULL,
  detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE idempotency_keys (
  actor text NOT NULL, key text NOT NULL, request_hash text NOT NULL,
  response jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor,key)
);
INSERT INTO schema_migrations(version) VALUES (1);
`;
