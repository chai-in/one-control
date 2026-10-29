import { expect, test } from "vitest";
import { createModuleRegistry, type ModuleDefinition } from "../src/module-registry.js";

const module = (id: string, overrides: Partial<ModuleDefinition> = {}): ModuleDefinition => ({
  id,
  dependencies: [],
  permissions: [],
  commands: [],
  routes: [],
  background: [],
  ...overrides,
});

test("resolves exact dependency closure with permissions and defaults to disabled", () => {
  const definitions = [
    module("inventory", { dependencies: ["identity"], commands: ["inventory.scan"] }),
    module("identity", { permissions: ["identity.read"] }),
    module("ema", { routes: ["GET /v1/integrations/ema/endpoints"], background: ["ema.poll"] }),
  ];
  const registry = createModuleRegistry(definitions);
  expect(registry.resolve([], [])).toEqual([]);
  expect(registry.resolve(["inventory"], ["identity.read"])).toEqual(["identity", "inventory"]);
  expect(() => registry.resolve(["inventory"], [])).toThrow("Module permission not granted");
  expect(() => registry.resolve(["unknown"], [])).toThrow("Unknown enabled module");
  expect(registry.commandOwner("inventory.scan")).toBe("inventory");
  expect(registry.routeOwner("GET /v1/integrations/ema/endpoints")).toBe("ema");
  expect(registry.backgroundOwner("ema.poll")).toBe("ema");
  expect(registry.commandOwner("unregistered")).toBeUndefined();
  expect(() => registry.requireEnabled("command", "unregistered", ["inventory"], ["identity.read"])).toThrow(
    "Unregistered module entrypoint",
  );
  expect(() => registry.requireEnabled("route", "GET /v1/integrations/ema/endpoints", [], [])).toThrow(
    "Module disabled",
  );
  expect(() => registry.requireEnabled("command", "inventory.scan", ["inventory"], [])).toThrow(
    "Module permission not granted",
  );
  expect(registry.requireEnabled("background", "ema.poll", ["ema"], [])).toBe("ema");
  definitions[0] = module("changed");
  expect(registry.commandOwner("inventory.scan")).toBe("inventory");
});

test("rejects conflicting ownership, unknown dependencies, cycles and malformed input", () => {
  for (const field of ["commands", "routes", "background"] as const) {
    const name = field === "routes" ? "POST /v1/example" : "example";
    expect(() =>
      createModuleRegistry([module("a", { [field]: [name] }), module("b", { [field]: [name] })]),
    ).toThrow("Duplicate entrypoint owner");
  }
  expect(() => createModuleRegistry([module("a"), module("a")])).toThrow("Invalid or duplicate module ID");
  expect(() => createModuleRegistry([module("a", { dependencies: ["absent"] })])).toThrow(
    "Unknown module dependency",
  );
  expect(() =>
    createModuleRegistry([module("a", { dependencies: ["b"] }), module("b", { dependencies: ["a"] })]),
  ).toThrow("Module dependency cycle");
  expect(() => createModuleRegistry([module("a", { commands: ["same", "same"] })])).toThrow();
  expect(() => createModuleRegistry([module("a", { routes: ["GET https://example.com"] })])).toThrow();
  expect(() => createModuleRegistry([module("a")]).resolve(["a", "a"], [])).toThrow();
});
