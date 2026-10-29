import { z } from "zod";

const id = z
  .string()
  .regex(/^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/)
  .max(96);
const version = z.string().regex(/^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/);
export const platformSchema = z.enum([
  "win-x64",
  "win-arm64",
  "osx-x64",
  "osx-arm64",
  "linux-x64",
  "linux-arm64",
]);
function validArtifactURL(value: string): boolean {
  const parts =
    /^https:\/\/(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?(\/[a-z0-9._~!$&'()*+,;=:@%/-]*)?(\?[a-z0-9._~!$&'()*+,;=:@%/?-]*)?$/i.exec(
      value,
    );
  if (!parts || parts[0] !== value || /%(?![0-9a-f]{2})/i.test(value)) return false;
  const host = parts[1] ?? "";
  if (parts[2] && Number(parts[2]) > 65535) return false;
  if (host.startsWith("[")) {
    try {
      new URL(`https://${host}`);
      return true;
    } catch {
      return false;
    }
  }
  const dns = host.endsWith(".") ? host.slice(0, -1) : host;
  if (
    dns.length > 253 ||
    !dns.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
  )
    return false;
  const last = dns.slice(dns.lastIndexOf(".") + 1);
  if (/^(?:[0-9]+|0x[0-9a-f]*)$/i.test(last)) {
    return (
      host === dns &&
      host.split(".").length === 4 &&
      host.split(".").every((part) => /^(?:0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255)
    );
  }
  return true;
}

export const artifactSchema = z
  .object({
    url: z.string().refine(validArtifactURL, "Module artifacts require an explicit absolute HTTPS URL"),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    size: z.int().min(1).max(2_147_483_648),
  })
  .strict();
export const moduleManifestSchema = z
  .object({
    schemaVersion: z.literal(1),
    id,
    version,
    kind: z.enum(["feature", "shared"]),
    minimumBootstrap: version,
    permissions: z
      .array(id)
      .max(32)
      .refine((values) => new Set(values).size === values.length),
    dependencies: z.record(id, version).refine((values) => Object.keys(values).length <= 32),
    artifacts: z.partialRecord(platformSchema, artifactSchema),
  })
  .strict();
export const moduleCatalogSchema = z.array(moduleManifestSchema).max(512);
export type ModuleManifest = z.infer<typeof moduleManifestSchema>;
export type ModulePlatform = z.infer<typeof platformSchema>;
const installedModuleSchema = z
  .object({
    id,
    version,
    sha256: artifactSchema.shape.sha256,
    size: artifactSchema.shape.size,
    active: z.boolean(),
    rollbackPinned: z.boolean().optional(),
    dependencies: moduleManifestSchema.shape.dependencies,
  })
  .strict();
export type InstalledModule = z.infer<typeof installedModuleSchema>;
export interface PlannedModule {
  key: string;
  manifest: ModuleManifest;
  artifact: z.infer<typeof artifactSchema>;
  requiredBy: string[];
  downloadRequired: boolean;
}
export interface ModulePlan {
  packages: PlannedModule[];
  deactivate: string[];
  removalCandidates: string[];
}
export class ModulePlanError extends Error {
  constructor(
    public readonly code: string,
    public readonly moduleKey: string,
  ) {
    super(`${code}: ${moduleKey}`);
  }
}
const keyOf = (module: Pick<ModuleManifest, "id" | "version">) => `${module.id}@${module.version}`;
function compareVersion(left: string, right: string): number {
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let index = 0; index < 3; index++) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference) return difference;
  }
  return 0;
}

function installedGraph(input: unknown): Map<string, InstalledModule> {
  const records = z.array(installedModuleSchema).max(512).parse(input);
  const graph = new Map<string, InstalledModule>();
  for (const module of records) {
    const key = keyOf(module);
    if (graph.has(key)) throw new ModulePlanError("duplicate_installed_module", key);
    graph.set(key, module);
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  function validate(key: string): void {
    if (visiting.has(key)) throw new ModulePlanError("installed_dependency_cycle", key);
    if (visited.has(key)) return;
    const module = graph.get(key);
    if (!module) throw new ModulePlanError("missing_installed_dependency", key);
    visiting.add(key);
    for (const [dependency, dependencyVersion] of Object.entries(module.dependencies))
      validate(`${dependency}@${dependencyVersion}`);
    visiting.delete(key);
    visited.add(key);
  }
  for (const key of graph.keys()) validate(key);
  return graph;
}

function rollbackClosure(installed: Map<string, InstalledModule>): Set<string> {
  const retained = new Set<string>();
  function retain(key: string): void {
    if (retained.has(key)) return;
    retained.add(key);
    const module = installed.get(key);
    if (!module) throw new ModulePlanError("missing_installed_dependency", key);
    for (const [dependency, dependencyVersion] of Object.entries(module.dependencies))
      retain(`${dependency}@${dependencyVersion}`);
  }
  for (const [key, module] of installed) if (module.rollbackPinned) retain(key);
  return retained;
}

// This pure planner never downloads or executes code. Its caller must first verify
// catalog signatures, expiry, revision, origin authorization and device policy.
export function resolveModulePlan(input: {
  catalog: unknown;
  enabled: Record<string, string>;
  disabled?: string[];
  platform: ModulePlatform;
  bootstrapVersion: string;
  allowedPermissions: string[];
  installed?: readonly InstalledModule[];
}): ModulePlan {
  const catalog = moduleCatalogSchema.parse(input.catalog);
  const enabled = z.record(id, version).parse(input.enabled);
  const platform = platformSchema.parse(input.platform);
  const bootstrap = version.parse(input.bootstrapVersion);
  const permissions = new Set(z.array(id).parse(input.allowedPermissions));
  const disabled = new Set(z.array(id).parse(input.disabled ?? []));
  const manifests = new Map<string, ModuleManifest>();
  for (const manifest of catalog) {
    const key = keyOf(manifest);
    if (manifests.has(key)) throw new ModulePlanError("duplicate_manifest", key);
    manifests.set(key, manifest);
  }
  const installed = installedGraph(input.installed ?? []);
  const retained = rollbackClosure(installed);
  const packages = new Map<string, PlannedModule>();
  const visiting = new Set<string>();
  function visit(key: string, root: string): void {
    if (visiting.has(key)) throw new ModulePlanError("dependency_cycle", key);
    const prior = packages.get(key);
    if (prior?.requiredBy.includes(root)) return;
    const manifest = manifests.get(key);
    if (!manifest) throw new ModulePlanError("missing_manifest", key);
    if (disabled.has(manifest.id)) throw new ModulePlanError("module_disabled", key);
    if (compareVersion(bootstrap, manifest.minimumBootstrap) < 0)
      throw new ModulePlanError("bootstrap_upgrade_required", key);
    if (manifest.permissions.some((permission) => !permissions.has(permission)))
      throw new ModulePlanError("permission_not_granted", key);
    const artifact = manifest.artifacts[platform];
    if (!artifact) throw new ModulePlanError("unsupported_platform", key);
    visiting.add(key);
    for (const [dependency, dependencyVersion] of Object.entries(manifest.dependencies).sort())
      visit(`${dependency}@${dependencyVersion}`, root);
    visiting.delete(key);
    if (prior) prior.requiredBy.push(root);
    else {
      const current = installed.get(key);
      packages.set(key, {
        key,
        manifest,
        artifact,
        requiredBy: [root],
        downloadRequired: current?.sha256 !== artifact.sha256 || current?.size !== artifact.size,
      });
    }
  }
  for (const [moduleId, moduleVersion] of Object.entries(enabled).sort()) {
    const key = `${moduleId}@${moduleVersion}`;
    const manifest = manifests.get(key);
    if (manifest?.kind === "shared") throw new ModulePlanError("feature_root_required", key);
    visit(key, moduleId);
  }
  return {
    packages: [...packages.values()].map((module) => ({ ...module, requiredBy: module.requiredBy.sort() })),
    deactivate: [...installed]
      .filter(([key, module]) => module.active && !packages.has(key))
      .map(([key]) => key)
      .sort(),
    removalCandidates: [...installed]
      .filter(([key]) => !packages.has(key) && !retained.has(key))
      .map(([key]) => key)
      .sort(),
  };
}
