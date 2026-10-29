export const nativeAuthoritySchema = [
  `CREATE TABLE native_custody_records (
    reference text PRIMARY KEY, root_version numeric(20,0) NOT NULL, authority_epoch numeric(20,0) NOT NULL,
    public_trust jsonb NOT NULL, trust_digest text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE native_publisher_evidence (
    envelope_digest text PRIMARY KEY, custody_reference text NOT NULL REFERENCES native_custody_records(reference),
    key_id text NOT NULL, publisher text NOT NULL, payload bytea NOT NULL, envelope bytea NOT NULL,
    projection jsonb NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE native_publication_sequences (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), kind text NOT NULL CHECK(kind IN ('catalog','policy')),
    subject text NOT NULL, revision numeric(20,0) NOT NULL CHECK(revision BETWEEN 1 AND 18446744073709551615),
    PRIMARY KEY(scope_id,kind,subject)
  )`,
  `CREATE TABLE native_publications (
    id uuid PRIMARY KEY, scope_id uuid NOT NULL REFERENCES management_scopes(id),
    kind text NOT NULL CHECK(kind IN ('catalog','policy')), enrollment_id uuid REFERENCES native_enrollments(id),
    custody_reference text NOT NULL REFERENCES native_custody_records(reference), root_version numeric(20,0) NOT NULL,
    authority_epoch numeric(20,0) NOT NULL, revision numeric(20,0) NOT NULL, authorization_version numeric(20,0) NOT NULL,
    request_hash text NOT NULL, issuer text NOT NULL, subject text NOT NULL, predecessor uuid,
    state text NOT NULL CHECK(state IN ('pending','published','superseded','quarantined')),
    protected_bytes bytea NOT NULL, payload bytea NOT NULL, payload_digest text NOT NULL, envelope bytea,
    projection jsonb NOT NULL, deadline timestamptz NOT NULL, expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), published_at timestamptz,
    CHECK((kind='catalog' AND enrollment_id IS NULL) OR (kind='policy' AND enrollment_id IS NOT NULL)),
    CHECK(revision BETWEEN 1 AND 18446744073709551615),
    CHECK(state<>'published' OR envelope IS NOT NULL)
  )`,
  `CREATE INDEX native_publication_scope ON native_publications(scope_id,kind,state)`,
  `CREATE TABLE native_catalog_heads (
    scope_id uuid PRIMARY KEY REFERENCES management_scopes(id), publication_id uuid NOT NULL REFERENCES native_publications(id)
  )`,
  `CREATE TABLE native_selections (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), platform text NOT NULL,
    version numeric(20,0) NOT NULL, catalog_id uuid NOT NULL REFERENCES native_publications(id),
    enabled jsonb NOT NULL, disabled jsonb NOT NULL, allowed_permissions jsonb NOT NULL,
    bootstrap_version text NOT NULL, issuer text NOT NULL, subject text NOT NULL,
    PRIMARY KEY(scope_id,platform)
  )`,
  `CREATE TABLE native_policy_heads (
    enrollment_id uuid PRIMARY KEY REFERENCES native_enrollments(id), publication_id uuid NOT NULL REFERENCES native_publications(id)
  )`,
  `CREATE TABLE native_nonce_receipts (
    enrollment_id uuid NOT NULL REFERENCES native_enrollments(id), nonce_hash text NOT NULL,
    credential_hash text NOT NULL, policy_id uuid NOT NULL REFERENCES native_publications(id),
    catalog_id uuid NOT NULL REFERENCES native_publications(id), response bytea,
    state text NOT NULL CHECK(state IN ('issued','expired','quarantined')),
    expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(enrollment_id,nonce_hash)
  )`,
] as const;
