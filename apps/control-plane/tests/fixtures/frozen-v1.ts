import type { TransactionQuery } from "../../src/database.js";
export const frozenV1Sql =
  "\nCREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());\nCREATE TABLE devices (\n  id uuid PRIMARY KEY, hostname text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 255),\n  ring text NOT NULL DEFAULT 'canary' CHECK (ring IN ('canary','pilot','broad')),\n  last_seen_at timestamptz, inventory jsonb, revoked_at timestamptz,\n  created_at timestamptz NOT NULL DEFAULT now()\n);\nCREATE TABLE enrollment_tokens (\n  hash text PRIMARY KEY, context text NOT NULL CHECK (context IN ('system','user')),\n  device_id uuid REFERENCES devices(id), expires_at timestamptz NOT NULL,\n  used_at timestamptz, created_by text NOT NULL,\n  CHECK (context = 'system' OR device_id IS NOT NULL)\n);\nCREATE TABLE credentials (\n  hash text PRIMARY KEY, device_id uuid NOT NULL REFERENCES devices(id),\n  context text NOT NULL CHECK (context IN ('system','user')),\n  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,\n  revoked_at timestamptz\n);\nCREATE TABLE releases (\n  id uuid PRIMARY KEY, package_id text NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),\n  envelope jsonb NOT NULL, manifest jsonb NOT NULL, created_by text NOT NULL,\n  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(package_id, sequence)\n);\nCREATE TABLE batches (\n  id uuid PRIMARY KEY, created_by text NOT NULL, approved_by text, command jsonb NOT NULL,\n  ring text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()\n);\nCREATE TABLE jobs (\n  id uuid PRIMARY KEY, batch_id uuid NOT NULL REFERENCES batches(id),\n  device_id uuid NOT NULL REFERENCES devices(id), context text NOT NULL,\n  kind text NOT NULL, command jsonb NOT NULL,\n  state text NOT NULL CHECK (state IN ('awaiting_approval','queued','leased','succeeded','failed','cancelled','indeterminate')),\n  starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),\n  lease_hash text, lease_expires_at timestamptz, attempt int NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),\n  result jsonb, created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,\n  UNIQUE(batch_id, device_id),\n  CHECK ((state = 'leased') = (lease_hash IS NOT NULL AND lease_expires_at IS NOT NULL))\n);\nCREATE INDEX jobs_dispatch ON jobs(device_id, context, state, starts_at);\nCREATE UNIQUE INDEX one_lease_per_device ON jobs(device_id) WHERE state = 'leased';\nCREATE TABLE audit_events (\n  sequence bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL, subject text NOT NULL,\n  detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()\n);\nCREATE TABLE idempotency_keys (\n  actor text NOT NULL, key text NOT NULL, request_hash text NOT NULL,\n  response jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor,key)\n);\nINSERT INTO schema_migrations(version) VALUES (1);\n";
export const frozenV1Units = Object.freeze([
  "CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());",
  "CREATE TABLE devices (\n  id uuid PRIMARY KEY, hostname text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 255),\n  ring text NOT NULL DEFAULT 'canary' CHECK (ring IN ('canary','pilot','broad')),\n  last_seen_at timestamptz, inventory jsonb, revoked_at timestamptz,\n  created_at timestamptz NOT NULL DEFAULT now()\n);",
  "CREATE TABLE enrollment_tokens (\n  hash text PRIMARY KEY, context text NOT NULL CHECK (context IN ('system','user')),\n  device_id uuid REFERENCES devices(id), expires_at timestamptz NOT NULL,\n  used_at timestamptz, created_by text NOT NULL,\n  CHECK (context = 'system' OR device_id IS NOT NULL)\n);",
  "CREATE TABLE credentials (\n  hash text PRIMARY KEY, device_id uuid NOT NULL REFERENCES devices(id),\n  context text NOT NULL CHECK (context IN ('system','user')),\n  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,\n  revoked_at timestamptz\n);",
  "CREATE TABLE releases (\n  id uuid PRIMARY KEY, package_id text NOT NULL, sequence bigint NOT NULL CHECK (sequence > 0),\n  envelope jsonb NOT NULL, manifest jsonb NOT NULL, created_by text NOT NULL,\n  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(package_id, sequence)\n);",
  "CREATE TABLE batches (\n  id uuid PRIMARY KEY, created_by text NOT NULL, approved_by text, command jsonb NOT NULL,\n  ring text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()\n);",
  "CREATE TABLE jobs (\n  id uuid PRIMARY KEY, batch_id uuid NOT NULL REFERENCES batches(id),\n  device_id uuid NOT NULL REFERENCES devices(id), context text NOT NULL,\n  kind text NOT NULL, command jsonb NOT NULL,\n  state text NOT NULL CHECK (state IN ('awaiting_approval','queued','leased','succeeded','failed','cancelled','indeterminate')),\n  starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),\n  lease_hash text, lease_expires_at timestamptz, attempt int NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),\n  result jsonb, created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,\n  UNIQUE(batch_id, device_id),\n  CHECK ((state = 'leased') = (lease_hash IS NOT NULL AND lease_expires_at IS NOT NULL))\n);",
  "CREATE INDEX jobs_dispatch ON jobs(device_id, context, state, starts_at);",
  "CREATE UNIQUE INDEX one_lease_per_device ON jobs(device_id) WHERE state = 'leased';",
  "CREATE TABLE audit_events (\n  sequence bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL, subject text NOT NULL,\n  detail jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()\n);",
  "CREATE TABLE idempotency_keys (\n  actor text NOT NULL, key text NOT NULL, request_hash text NOT NULL,\n  response jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(actor,key)\n);",
  "INSERT INTO schema_migrations(version) VALUES (1);",
] as const);
export const baselineTables = Object.freeze([
  "audit_events",
  "batches",
  "credentials",
  "devices",
  "enrollment_tokens",
  "idempotency_keys",
  "jobs",
  "releases",
  "schema_migrations",
] as const);
export const baselineMutations = [
  ["check", ["ALTER TABLE devices DROP CONSTRAINT devices_hostname_check"]],
  ["default", ["ALTER TABLE devices ALTER COLUMN ring SET DEFAULT 'pilot'"]],
  ["type", ["ALTER TABLE devices ALTER COLUMN hostname TYPE varchar(255)"]],
  ["nullability", ["ALTER TABLE devices ALTER COLUMN hostname DROP NOT NULL"]],
  ["index", ["DROP INDEX jobs_dispatch"]],
  [
    "predicate",
    [
      "DROP INDEX one_lease_per_device",
      "CREATE UNIQUE INDEX one_lease_per_device ON jobs(device_id) WHERE state='queued'",
    ],
  ],
  ["extra", ["CREATE TABLE extra(id int)"]],
  ["missing", ["DROP TABLE idempotency_keys"]],
  ["dropped", ["ALTER TABLE devices ADD COLUMN extra int", "ALTER TABLE devices DROP COLUMN extra"]],
  ["routine", ["CREATE FUNCTION extra() RETURNS int LANGUAGE sql AS 'SELECT 1'"]],
  ["enum", ["CREATE TYPE extra AS ENUM ('x')"]],
  ["domain", ["CREATE DOMAIN extra AS int CHECK (VALUE>0)"]],
  ["composite", ["CREATE TYPE extra AS (id int)"]],
  ["view", ["CREATE VIEW extra AS SELECT id FROM devices"]],
  [
    "policy",
    ["ALTER TABLE devices ENABLE ROW LEVEL SECURITY", "CREATE POLICY extra ON devices USING (true)"],
  ],
  ["rule", ["CREATE RULE extra AS ON INSERT TO devices DO ALSO NOTHING"]],
  ["marker", ["DELETE FROM schema_migrations"]],
  ["markerExtra", ["INSERT INTO schema_migrations(version) VALUES(2)"]],
  ["markerMissing", ["DROP TABLE schema_migrations"]],
  ["foreignKey", ["ALTER TABLE credentials DROP CONSTRAINT credentials_device_id_fkey"]],
  ["sequence", ["ALTER SEQUENCE audit_events_sequence_seq OWNED BY NONE"]],
  ["collation", ['CREATE COLLATION extra FROM pg_catalog."C"']],
  ["inheritance", ["CREATE TABLE parent()", "ALTER TABLE devices INHERIT parent"]],
  [
    "enforcement",
    [
      "ALTER TABLE devices DROP CONSTRAINT devices_hostname_check",
      "ALTER TABLE devices ADD CONSTRAINT devices_hostname_check CHECK (length(hostname) BETWEEN 1 AND 255) NOT ENFORCED",
    ],
  ],
  [
    "temporaryMarker",
    [
      "DELETE FROM schema_migrations",
      "CREATE TEMP TABLE schema_migrations(version int)",
      "INSERT INTO pg_temp.schema_migrations VALUES(1)",
    ],
  ],
  [
    "unsafeDependency",
    [
      "CREATE TEMP TABLE temporary_namespace(id int)",
      "CREATE DOMAIN pg_temp.external_type AS text",
      "ALTER TABLE devices ADD CONSTRAINT extra CHECK ('x'::pg_temp.external_type::text='x')",
    ],
  ],
  [
    "operator",
    [
      "CREATE TEMP TABLE operator_calls(calls int)",
      "CREATE FUNCTION pg_temp.unsafe_oid_equal(pg_catalog.oid,pg_catalog.oid) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN INSERT INTO pg_temp.operator_calls VALUES(1); RETURN $1 OPERATOR(pg_catalog.=) $2; END $$",
      "CREATE OPERATOR = (LEFTARG=pg_catalog.oid,RIGHTARG=pg_catalog.oid,FUNCTION=pg_temp.unsafe_oid_equal)",
    ],
  ],
] as const;
export async function baselineBoundary(tx: TransactionQuery, namespace: string) {
  await tx.query("SELECT pg_advisory_xact_lock(748391234)");
  await tx.query(`SET LOCAL search_path TO "${namespace.replaceAll('"', '""')}", pg_catalog`);
  const tables = await tx.query(
    "SELECT relname FROM pg_catalog.pg_class WHERE relnamespace=pg_catalog.to_regnamespace($1) AND relkind='r' ORDER BY relname",
    [namespace],
  );
  for (const { relname } of tables) {
    if (baselineTables.includes(relname as (typeof baselineTables)[number]))
      await tx.query(
        'LOCK TABLE "' +
          namespace.replaceAll('"', '""') +
          '"."' +
          String(relname).replaceAll('"', '""') +
          '" IN ACCESS EXCLUSIVE MODE',
      );
  }
}
export async function independentCatalog(tx: TransactionQuery, namespace: string) {
  const relations = await tx.query(
    "SELECT c.relname,c.relkind,a.attname,a.attnum,a.attisdropped,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS default FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid OPERATOR(pg_catalog.=) c.oid AND a.attnum>0 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid OPERATOR(pg_catalog.=) c.oid AND d.adnum OPERATOR(pg_catalog.=) a.attnum WHERE c.relnamespace OPERATOR(pg_catalog.=) pg_catalog.to_regnamespace($1) ORDER BY c.relname,a.attnum",
    [namespace],
  );
  const constraints = await tx.query(
    "SELECT k.conname,pg_catalog.pg_get_constraintdef(k.oid) AS definition FROM pg_catalog.pg_constraint k WHERE k.connamespace OPERATOR(pg_catalog.=) pg_catalog.to_regnamespace($1) ORDER BY k.conname",
    [namespace],
  );
  const indexes = await tx.query(
    "SELECT c.relname,pg_catalog.pg_get_indexdef(c.oid) AS definition FROM pg_catalog.pg_class c WHERE c.relnamespace OPERATOR(pg_catalog.=) pg_catalog.to_regnamespace($1) AND c.relkind OPERATOR(pg_catalog.=) 'i' ORDER BY c.relname",
    [namespace],
  );
  const routines = await tx.query(
    "SELECT proname FROM pg_catalog.pg_proc WHERE pronamespace OPERATOR(pg_catalog.=) pg_catalog.to_regnamespace($1) ORDER BY proname",
    [namespace],
  );
  return JSON.stringify({ relations, constraints, indexes, routines });
}
export async function seedBaselineRows(tx: TransactionQuery, id: string) {
  await tx.query("INSERT INTO devices(id,hostname,inventory) VALUES($1,'preserved','{\"os\":\"fixture\"}')", [
    id,
  ]);
  await tx.query(
    "INSERT INTO enrollment_tokens(hash,context,device_id,expires_at,created_by) VALUES('fixture-enrollment','system',$1,now()+interval '1 day','test')",
    [id],
  );
  await tx.query(
    "INSERT INTO credentials(hash,device_id,context,expires_at) VALUES('fixture-credential',$1,'system',now()+interval '1 day')",
    [id],
  );
  await tx.query(
    "INSERT INTO releases(id,package_id,sequence,envelope,manifest,created_by) VALUES($1,'fixture',1,'{}','{}','test')",
    [id],
  );
  await tx.query("INSERT INTO batches(id,created_by,command,ring) VALUES($1,'test','{}','canary')", [id]);
  await tx.query(
    "INSERT INTO jobs(id,batch_id,device_id,context,kind,command,state,starts_at,ends_at,result,finished_at) VALUES($1,$1,$1,'system','fixture','{}','succeeded',now(),now()+interval '1 hour','{\"receipt\":\"retained\"}',now())",
    [id],
  );
  await tx.query("INSERT INTO audit_events(actor,action,subject,detail) VALUES('test','preserved',$1,'{}')", [
    id,
  ]);
  await tx.query(
    "INSERT INTO idempotency_keys(actor,key,request_hash,response) VALUES('test','fixture','fixture-hash','{}')",
  );
}
export async function baselineRows(tx: TransactionQuery) {
  const rows = [];
  const [identity] = await tx.query("SELECT pg_catalog.current_schema() AS namespace");
  const namespace = String(identity?.namespace).replaceAll('"', '""');
  for (const table of baselineTables) {
    const relation = `"${namespace}"."${table}"`;
    const [exists] = await tx.query("SELECT pg_catalog.to_regclass($1)::pg_catalog.text AS relation", [
      relation,
    ]);
    rows.push(
      exists?.relation
        ? await tx.query(
            `SELECT pg_catalog.to_jsonb(t) AS row FROM ${relation} t ORDER BY pg_catalog.to_jsonb(t)::pg_catalog.text LIMIT 128`,
          )
        : null,
    );
  }
  return JSON.stringify(rows);
}
