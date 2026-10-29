// Code generated from schema/wire.json; DO NOT EDIT.
export interface PackageFile {
  path: string;
  sha256: string;
  size: number;
}
export interface PackageAttestation {
  schemaVersion: 1;
  id: string;
  version: string;
  platform: string;
  publisher: string;
  layout: "passive-v1" | "native-host-v1";
  archiveSha256: string;
  archiveSize: number;
  files: PackageFile[];
  issuedAt: number;
  expiresAt: number;
}
export interface Envelope {
  protected: string;
  payload: string;
  signature: string;
}
export interface Protected {
  schemaVersion: 1;
  domain: string;
  alg: "PS256";
  rootVersion: string;
  keyId: string;
}
export interface Scope {
  kind: "machine" | "user";
  machineId: string;
  principal?: string;
  sessionId?: string;
  sessionIncarnation?: string;
  localNonce?: string;
}
export interface Policy {
  schemaVersion: 1;
  authorityEpoch: string;
  revision: string;
  deviceId: string;
  enrollmentId: string;
  platform: string;
  scope: Scope;
  catalogDigest: string;
  enabled: Record<string, string>;
  disabled: string[];
  allowedPermissions: string[];
  issuedAt: number;
  expiresAt: number;
}
export interface Freshness {
  schemaVersion: 1;
  authorityEpoch: string;
  deviceId: string;
  enrollmentId: string;
  policyDigest: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
}
export interface Artifact {
  url: string;
  sha256: string;
  size: number;
}
export interface Manifest {
  schemaVersion: 1;
  id: string;
  version: string;
  kind: "feature" | "shared";
  minimumBootstrap: string;
  permissions: string[];
  dependencies: Record<string, string>;
  artifacts: Record<string, Artifact>;
}
export interface Installed {
  id: string;
  version: string;
  sha256: string;
  size: number;
  active: boolean;
  rollbackPinned?: boolean;
  dependencies: Record<string, string>;
}
export interface PlanInput {
  catalog: Manifest[];
  enabled: Record<string, string>;
  disabled?: string[];
  platform: string;
  bootstrapVersion: string;
  allowedPermissions: string[];
  installed?: Installed[];
}
export interface Planned {
  key: string;
  manifest: Manifest;
  artifact: Artifact;
  requiredBy: string[];
  downloadRequired: boolean;
}
export interface Plan {
  packages: Planned[];
  deactivate: string[];
  removalCandidates: string[];
}
export interface Checkpoint {
  rootVersion: string;
  authorityEpoch: string;
  revision: string;
  policyDigest: string;
  bindingDigest: string;
  seenAt: number;
  nonce: string;
}
export interface CatalogPlatform {
  publisher: string;
  layout: "passive-v1" | "native-host-v1";
  hostAbi: "none" | "one-control-host-v1";
  scope: "machine";
  attestationSha256: string;
}
export interface CatalogEntry {
  manifest: Manifest;
  platforms: Record<string, CatalogPlatform>;
}
export interface ModuleCatalog {
  schemaVersion: 2;
  authorityEpoch: string;
  revision: string;
  issuedAt: number;
  expiresAt: number;
  entries: CatalogEntry[];
}
export interface CatalogFloor {
  rootVersion: string;
  authorityEpoch: string;
  revision: string;
  digest: string;
}
export interface PublishedPackage {
  identity: string;
  entry: CatalogEntry;
  platform: string;
  attestation: string;
  verifiedAt: number;
  state: "intent" | "published";
}
export interface Generation {
  identity: string;
  packages: string[];
  roots: Record<string, string>;
}
export interface HostAttempt {
  instance: string;
  generation: string;
  package: string;
  state: "intent" | "stopped" | "unknown";
}
export interface LifecycleState {
  schemaVersion: 1;
  sequence: string;
  checkpoint: Checkpoint;
  catalogFloor: CatalogFloor;
  policyEnvelope: string;
  catalogEnvelope: string;
  packages: PublishedPackage[];
  generations: Generation[];
  attempts: HostAttempt[];
  candidate: string;
  active: string;
  healthy: string;
  trash: string[];
  freshnessEnvelope: string;
}
export interface WireModels {
  PackageFile: PackageFile;
  PackageAttestation: PackageAttestation;
  Envelope: Envelope;
  Protected: Protected;
  Scope: Scope;
  Policy: Policy;
  Freshness: Freshness;
  Artifact: Artifact;
  Manifest: Manifest;
  Installed: Installed;
  PlanInput: PlanInput;
  Planned: Planned;
  Plan: Plan;
  Checkpoint: Checkpoint;
  CatalogPlatform: CatalogPlatform;
  CatalogEntry: CatalogEntry;
  ModuleCatalog: ModuleCatalog;
  CatalogFloor: CatalogFloor;
  PublishedPackage: PublishedPackage;
  Generation: Generation;
  HostAttempt: HostAttempt;
  LifecycleState: LifecycleState;
}
export const wireSchema = {
  version: 1,
  limits: {
    envelopeBytes: 6291456,
    protectedBytes: 4096,
    payloadBytes: 4194304,
  },
  patterns: {
    id: "^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$",
    version: "^(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})$",
    decimal: "^(0|[1-9][0-9]{0,19})$",
    digest: "^[a-f0-9]{64}$",
    nonce: "^[A-Za-z0-9_-]{43}$",
  },
  types: {
    PackageFile: {
      path: "string",
      sha256: "digest",
      size: "size",
    },
    PackageAttestation: {
      schemaVersion: "literal:1",
      id: "id",
      version: "version",
      platform: "platform",
      publisher: "id",
      layout: "enum:passive-v1,native-host-v1",
      archiveSha256: "digest",
      archiveSize: "size",
      files: "array:PackageFile",
      issuedAt: "timestamp",
      expiresAt: "timestamp",
    },
    Envelope: {
      protected: "string",
      payload: "string",
      signature: "string",
    },
    Protected: {
      schemaVersion: "literal:1",
      domain: "domain",
      alg: "literal:PS256",
      rootVersion: "decimal",
      keyId: "id",
    },
    Scope: {
      kind: "enum:machine,user",
      machineId: "identity",
      "principal?": "identity",
      "sessionId?": "identity",
      "sessionIncarnation?": "nonce",
      "localNonce?": "nonce",
    },
    Policy: {
      schemaVersion: "literal:1",
      authorityEpoch: "decimal",
      revision: "decimal",
      deviceId: "identity",
      enrollmentId: "identity",
      platform: "platform",
      scope: "Scope",
      catalogDigest: "digest",
      enabled: "map:version",
      disabled: "array:id",
      allowedPermissions: "array:id",
      issuedAt: "timestamp",
      expiresAt: "timestamp",
    },
    Freshness: {
      schemaVersion: "literal:1",
      authorityEpoch: "decimal",
      deviceId: "identity",
      enrollmentId: "identity",
      policyDigest: "digest",
      nonce: "nonce",
      issuedAt: "timestamp",
      expiresAt: "timestamp",
    },
    Artifact: {
      url: "https",
      sha256: "digest",
      size: "size",
    },
    Manifest: {
      schemaVersion: "literal:1",
      id: "id",
      version: "version",
      kind: "enum:feature,shared",
      minimumBootstrap: "version",
      permissions: "array:id",
      dependencies: "map:version",
      artifacts: "platformmap:Artifact",
    },
    Installed: {
      id: "id",
      version: "version",
      sha256: "digest",
      size: "size",
      active: "boolean",
      "rollbackPinned?": "boolean",
      dependencies: "map:version",
    },
    PlanInput: {
      catalog: "array:Manifest",
      enabled: "map:version",
      "disabled?": "array:id",
      platform: "platform",
      bootstrapVersion: "version",
      allowedPermissions: "array:id",
      "installed?": "array:Installed",
    },
    Planned: {
      key: "string",
      manifest: "Manifest",
      artifact: "Artifact",
      requiredBy: "array:string",
      downloadRequired: "boolean",
    },
    Plan: {
      packages: "array:Planned",
      deactivate: "array:string",
      removalCandidates: "array:string",
    },
    Checkpoint: {
      rootVersion: "decimal",
      authorityEpoch: "decimal",
      revision: "decimal",
      policyDigest: "digest",
      bindingDigest: "digest",
      seenAt: "timestamp",
      nonce: "nonce",
    },
    CatalogPlatform: {
      publisher: "id",
      layout: "enum:passive-v1,native-host-v1",
      hostAbi: "enum:none,one-control-host-v1",
      scope: "enum:machine",
      attestationSha256: "digest",
    },
    CatalogEntry: {
      manifest: "Manifest",
      platforms: "platformmap:CatalogPlatform",
    },
    ModuleCatalog: {
      schemaVersion: "literal:2",
      authorityEpoch: "decimal",
      revision: "decimal",
      issuedAt: "timestamp",
      expiresAt: "timestamp",
      entries: "array:CatalogEntry",
    },
    CatalogFloor: {
      rootVersion: "decimal",
      authorityEpoch: "decimal",
      revision: "decimal",
      digest: "digest",
    },
    PublishedPackage: {
      identity: "digest",
      entry: "CatalogEntry",
      platform: "platform",
      attestation: "string",
      verifiedAt: "timestamp",
      state: "enum:intent,published",
    },
    Generation: {
      identity: "digest",
      packages: "array:digest",
      roots: "map:version",
    },
    HostAttempt: {
      instance: "digest",
      generation: "digest",
      package: "digest",
      state: "enum:intent,stopped,unknown",
    },
    LifecycleState: {
      schemaVersion: "literal:1",
      sequence: "decimal",
      checkpoint: "Checkpoint",
      catalogFloor: "CatalogFloor",
      policyEnvelope: "string",
      catalogEnvelope: "string",
      packages: "array:PublishedPackage",
      generations: "array:Generation",
      attempts: "array:HostAttempt",
      candidate: "string",
      active: "string",
      healthy: "string",
      trash: "array:digest",
      freshnessEnvelope: "string",
    },
  },
  domains: [
    "root.v1",
    "module-catalog.v2",
    "device-policy.v1",
    "policy-freshness.v1",
    "bootstrap-release.v1",
    "publisher-attestation.v1",
  ],
  platforms: ["win-x64", "win-arm64", "osx-x64", "osx-arm64", "linux-x64", "linux-arm64"],
  errors: [
    "invalid_wire",
    "invalid_signature",
    "untrusted_key",
    "wrong_role",
    "wrong_root",
    "wrong_binding",
    "expired",
    "clock_rollback",
    "stale_epoch",
    "stale_revision",
    "equivocation",
    "replayed_challenge",
    "invalid_checkpoint",
    "checkpoint_conflict",
    "duplicate_manifest",
    "duplicate_installed_module",
    "installed_dependency_cycle",
    "missing_installed_dependency",
    "dependency_cycle",
    "missing_manifest",
    "module_disabled",
    "bootstrap_upgrade_required",
    "permission_not_granted",
    "unsupported_platform",
    "feature_root_required",
  ],
} as const;
