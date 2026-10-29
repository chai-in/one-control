/** Scoped desktop policy state. Configuration is retained; restore aborts rollout execution. */
export const desktopPolicySchema = [
  `CREATE TABLE desktop_policies (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), id text NOT NULL,
    version numeric(20,0) NOT NULL CHECK(version BETWEEN 1 AND 18446744073709551615),
    document jsonb NOT NULL, digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),
    deleted_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(scope_id,id)
  )`,
  `CREATE TABLE desktop_policy_versions (
    scope_id uuid NOT NULL, policy_id text NOT NULL, version numeric(20,0) NOT NULL,
    document jsonb NOT NULL, digest text NOT NULL, actor text NOT NULL, reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(scope_id,policy_id,version),
    FOREIGN KEY(scope_id,policy_id) REFERENCES desktop_policies(scope_id,id)
  )`,
  `CREATE TABLE desktop_groups (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), id uuid NOT NULL, name text NOT NULL,
    policy_id text, PRIMARY KEY(scope_id,id),
    FOREIGN KEY(scope_id,policy_id) REFERENCES desktop_policies(scope_id,id)
  )`,
  `CREATE TABLE desktop_assignments (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), device_id uuid NOT NULL REFERENCES devices(id),
    enrollment_id uuid NOT NULL, group_id uuid, policy_id text, PRIMARY KEY(scope_id,device_id),
    FOREIGN KEY(enrollment_id,device_id) REFERENCES native_enrollments(id,device_id),
    FOREIGN KEY(scope_id,group_id) REFERENCES desktop_groups(scope_id,id),
    FOREIGN KEY(scope_id,policy_id) REFERENCES desktop_policies(scope_id,id)
  )`,
  `CREATE TABLE desktop_fleets (
    scope_id uuid PRIMARY KEY REFERENCES management_scopes(id), default_policy_id text,
    FOREIGN KEY(scope_id,default_policy_id) REFERENCES desktop_policies(scope_id,id)
  )`,
  `CREATE TABLE desktop_policy_canaries (
    scope_id uuid NOT NULL, id uuid NOT NULL, policy_id text NOT NULL,
    base_version numeric(20,0) NOT NULL, candidate jsonb NOT NULL, digest text NOT NULL,
    state text NOT NULL CHECK(state IN ('pending','healthy','promoted','aborted')),
    actor text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
    PRIMARY KEY(scope_id,id), FOREIGN KEY(scope_id,policy_id) REFERENCES desktop_policies(scope_id,id)
  )`,
  `CREATE UNIQUE INDEX desktop_one_active_canary ON desktop_policy_canaries(scope_id,policy_id) WHERE state IN ('pending','healthy')`,
  `CREATE TABLE desktop_canary_targets (
    scope_id uuid NOT NULL, canary_id uuid NOT NULL, device_id uuid NOT NULL, enrollment_id uuid NOT NULL,
    observed_digest text, observed_at timestamptz, observation_reference text,
    PRIMARY KEY(scope_id,canary_id,device_id),
    FOREIGN KEY(scope_id,canary_id) REFERENCES desktop_policy_canaries(scope_id,id),
    FOREIGN KEY(enrollment_id,device_id) REFERENCES native_enrollments(id,device_id)
  )`,
] as const;
