export const assetSchema = [
  `CREATE TABLE company_people (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), id uuid NOT NULL,
    name text NOT NULL, email text, department text, employee_code text, title text, location text,
    identity_issuer text, identity_subject text,
    state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','offboarded')),
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), offboarded_at timestamptz,
    PRIMARY KEY(scope_id,id)
  )`,
  `CREATE UNIQUE INDEX company_people_email ON company_people(scope_id,lower(email)) WHERE email IS NOT NULL`,
  `CREATE TABLE managed_assets (
    scope_id uuid NOT NULL REFERENCES management_scopes(id), id uuid NOT NULL,
    kind text NOT NULL CHECK(kind IN ('windows','macos','other')), identifier text NOT NULL,
    identifier_type text NOT NULL CHECK(identifier_type IN ('asset-tag','serial','hostname','other')),
    label text NOT NULL, employee_id uuid, notes text NOT NULL DEFAULT '',
    state text NOT NULL CHECK(state IN ('stock','assigned','repair','lost','retired')),
    assigned_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(scope_id,id), FOREIGN KEY(scope_id,employee_id) REFERENCES company_people(scope_id,id)
  )`,
  `CREATE TABLE asset_links (
    scope_id uuid NOT NULL, asset_id uuid NOT NULL,
    source text NOT NULL CHECK(source IN ('native','falcon','ema')), source_ref text NOT NULL,
    verification text NOT NULL CHECK(verification IN ('native-enrollment','operator-recorded')),
    recorded_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(scope_id,source,source_ref), UNIQUE(scope_id,asset_id,source),
    FOREIGN KEY(scope_id,asset_id) REFERENCES managed_assets(scope_id,id)
  )`,
] as const;
