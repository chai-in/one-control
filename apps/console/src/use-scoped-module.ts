import { useEffect, useRef, useState } from "react";

export type ScopedApi = <T>(path: string, body?: unknown, method?: string) => Promise<T>;
type Settings = {
  version: string;
  permissionCeiling: string[];
  selectedRoots: string[];
  registeredModules: { id: string; dependencies: string[] }[];
  modules: { module_id: string; state: string }[];
};
export function useScopedModule<T extends { version: string }>(
  api: ScopedApi,
  isCurrent: () => boolean,
  moduleId: string,
  permission: string,
  suffix: string,
) {
  const [scopes, setScopes] = useState<{ id: string; name: string; kind: string }[]>([]);
  const [scopeId, setScopeId] = useState("");
  const [settings, setSettings] = useState<Settings | null>(null);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const selected = useRef("");
  const sequence = useRef(0);
  useEffect(() => {
    let live = true;
    api<{ scopes: { id: string; name: string; kind: string }[] }>("/v1/scopes")
      .then((result) => {
        if (live && isCurrent()) setScopes(result.scopes);
      })
      .catch((failure) => {
        if (live && isCurrent()) setError(failure.message);
      });
    return () => {
      live = false;
      sequence.current++;
    };
  }, [api, isCurrent]);
  async function load(id = selected.current) {
    const request = ++sequence.current;
    const current = () => isCurrent() && request === sequence.current && selected.current === id;
    setBusy(true);
    setError("");
    setSettings(null);
    setData(null);
    try {
      const config = await api<Settings>(`/v1/scopes/${id}/modules`);
      if (!current()) return;
      setSettings(config);
      if (config.modules.some((module) => module.module_id === moduleId && module.state === "enabled")) {
        const result = await api<T>(`/v1/scopes/${id}/${suffix}`);
        if (current()) setData(result);
      }
    } catch (failure) {
      if (current()) setError((failure as Error).message);
    } finally {
      if (current()) setBusy(false);
    }
  }
  function select(id: string) {
    selected.current = id;
    setScopeId(id);
    setData(null);
    setSettings(null);
    if (id) void load(id);
  }
  async function action(work: () => Promise<void>) {
    const id = selected.current;
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (failure) {
      if (isCurrent() && id === selected.current) setError((failure as Error).message);
    } finally {
      if (isCurrent() && id === selected.current) setBusy(false);
    }
  }
  async function enable(enabled: boolean) {
    if (!settings) return;
    await action(async () => {
      let expectedVersion = settings.version;
      if (enabled && permission && !settings.permissionCeiling.includes(permission))
        expectedVersion = (
          await api<{ version: string }>(
            `/v1/scopes/${scopeId}/permissions`,
            { expectedVersion, permissions: [...settings.permissionCeiling, permission] },
            "PUT",
          )
        ).version;
      function dependsOn(id: string, target: string): boolean {
        return (
          id === target ||
          (settings!.registeredModules.find((module) => module.id === id)?.dependencies ?? []).some(
            (dependency) => dependsOn(dependency, target),
          )
        );
      }
      const modules = settings.selectedRoots.filter((id) =>
        enabled ? id !== moduleId : !dependsOn(id, moduleId),
      );
      if (enabled) modules.push(moduleId);
      await api(`/v1/scopes/${scopeId}/server-modules`, { expectedVersion, enabled: modules }, "PUT");
      if (isCurrent() && selected.current === scopeId) await load(scopeId);
    });
  }
  async function mutate<R>(path: string, body: object, method = "PUT") {
    if (!data) return;
    const id = scopeId;
    const result = await api<R>(
      `/v1/scopes/${id}${path}`,
      { ...body, expectedVersion: data.version },
      method,
    );
    if (isCurrent() && selected.current === id) await load(id);
    return result;
  }
  return { scopes, scopeId, settings, data, error, busy, select, load, action, enable, mutate };
}
