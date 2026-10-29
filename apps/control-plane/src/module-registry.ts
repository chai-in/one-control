/** Module metadata only. Enforcement still requires the transaction-owned admission boundary. */
export type ModuleDefinition = Readonly<{
  id: string;
  dependencies: readonly string[];
  permissions: readonly string[];
  commands: readonly string[];
  routes: readonly string[];
  background: readonly string[];
}>;

export type ModuleRegistry = Readonly<{
  modules: readonly ModuleDefinition[];
  commandOwner: (name: string) => string | undefined;
  routeOwner: (name: string) => string | undefined;
  backgroundOwner: (name: string) => string | undefined;
  resolve: (enabled: readonly string[], allowedPermissions: readonly string[]) => readonly string[];
  requireEnabled: (
    kind: "command" | "route" | "background",
    name: string,
    enabled: readonly string[],
    allowedPermissions: readonly string[],
  ) => string;
}>;

const moduleId = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const entrypoint = /^[A-Za-z0-9][A-Za-z0-9./:_-]{0,199}$/;
const route = /^(GET|POST|PUT|PATCH|DELETE) \/[A-Za-z0-9/:._-]*$/;
const maxModules = 256;
const maxItems = 128;

function checkedList(values: readonly string[], pattern: RegExp): string[] {
  if (!Array.isArray(values) || values.length > maxItems) throw new Error("Invalid module entries");
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string" || value.length > 200 || !pattern.test(value) || seen.has(value))
      throw new Error("Invalid or duplicate module entry");
    seen.add(value);
  }
  return [...seen];
}

export function createModuleRegistry(definitions: readonly ModuleDefinition[]): ModuleRegistry {
  if (!Array.isArray(definitions) || definitions.length > maxModules) throw new Error("Invalid modules");
  const modules = new Map<string, ModuleDefinition>();
  const commands = new Map<string, string>();
  const routes = new Map<string, string>();
  const background = new Map<string, string>();
  const claim = (map: Map<string, string>, values: readonly string[], owner: string) => {
    for (const value of values) {
      if (map.has(value)) throw new Error("Duplicate entrypoint owner");
      map.set(value, owner);
    }
  };
  for (const input of definitions) {
    if (
      !input ||
      typeof input.id !== "string" ||
      input.id.length > 200 ||
      !moduleId.test(input.id) ||
      modules.has(input.id)
    )
      throw new Error("Invalid or duplicate module ID");
    const value = Object.freeze({
      id: input.id,
      dependencies: Object.freeze(checkedList(input.dependencies, moduleId)),
      permissions: Object.freeze(checkedList(input.permissions, moduleId)),
      commands: Object.freeze(checkedList(input.commands, entrypoint)),
      routes: Object.freeze(checkedList(input.routes, route)),
      background: Object.freeze(checkedList(input.background, entrypoint)),
    });
    modules.set(value.id, value);
    claim(commands, value.commands, value.id);
    claim(routes, value.routes, value.id);
    claim(background, value.background, value.id);
  }
  const ordered: string[] = [];
  const visiting = new Set<string>();
  const visited = new Set<string>();
  function visit(id: string): void {
    if (visited.has(id)) return;
    if (visiting.has(id)) throw new Error("Module dependency cycle");
    const value = modules.get(id);
    if (!value) throw new Error("Unknown module dependency");
    visiting.add(id);
    for (const dependency of value.dependencies) visit(dependency);
    visiting.delete(id);
    visited.add(id);
    ordered.push(id);
  }
  for (const id of modules.keys()) visit(id);
  function resolve(enabled: readonly string[], allowedPermissions: readonly string[]): readonly string[] {
    const roots = checkedList(enabled, moduleId);
    const allowed = new Set(checkedList(allowedPermissions, moduleId));
    const selected = new Set<string>();
    function include(id: string): void {
      if (selected.has(id)) return;
      const value = modules.get(id);
      if (!value) throw new Error("Unknown enabled module");
      if (value.permissions.some((permission) => !allowed.has(permission)))
        throw new Error("Module permission not granted");
      selected.add(id);
      for (const dependency of value.dependencies) include(dependency);
    }
    for (const id of roots) include(id);
    return Object.freeze(ordered.filter((id) => selected.has(id)));
  }
  return Object.freeze({
    modules: Object.freeze([...modules.values()]),
    commandOwner: (name: string) => commands.get(name),
    routeOwner: (name: string) => routes.get(name),
    backgroundOwner: (name: string) => background.get(name),
    resolve,
    requireEnabled(kind, name, enabled, allowedPermissions) {
      const owners = { command: commands, route: routes, background };
      const owner = owners[kind]?.get(name);
      if (!owner) throw new Error("Unregistered module entrypoint");
      if (!resolve(enabled, allowedPermissions).includes(owner)) throw new Error("Module disabled");
      return owner;
    },
  });
}
