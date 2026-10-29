import { useEffect, useRef, useState } from "react";
import type { ScopedApi } from "./use-scoped-module.js";
import "../../../modules/desktop-policies/console/desktop.css";

type Scope = { id: string; name: string; kind: "personal" | "company" };
type Grant = { issuer: string; subject: string; permission: string; revoked_at: string | null };
type Settings = Scope & {
  version: string;
  actorPermissions: string[];
  permissionCeiling: string[];
  selectedRoots: string[];
  registeredModules: { id: string; dependencies: string[]; permissions: string[] }[];
  modules: { module_id: string; state: string }[];
};
const access = ["owner", "view", "enroll", "configure", "approve", "command", "reveal"];

export function ScopesPanel({
  api,
  isCurrent,
  canEdit,
}: {
  api: ScopedApi;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeId, setScopeId] = useState("");
  const [settings, setSettings] = useState<Settings | null>(null);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [ceiling, setCeiling] = useState<string[]>([]);
  const [roots, setRoots] = useState<string[]>([]);
  const [customPermission, setCustomPermission] = useState("");
  const [issuer, setIssuer] = useState("");
  const [subject, setSubject] = useState("");
  const [permission, setPermission] = useState("view");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Scope["kind"]>("company");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const selected = useRef("");
  const sequence = useRef(0);
  const creation = useRef<{ id: string; name: string; kind: Scope["kind"] } | null>(null);
  useEffect(() => {
    let mounted = true;
    api<{ scopes: Scope[] }>("/v1/scopes")
      .then((result) => {
        if (mounted && isCurrent()) setScopes(result.scopes);
      })
      .catch((failure) => {
        if (mounted && isCurrent()) setError(failure.message);
      });
    return () => {
      mounted = false;
      sequence.current++;
      selected.current = "";
    };
  }, [api, isCurrent]);
  async function load(id = selected.current) {
    const request = ++sequence.current;
    const current = () => isCurrent() && sequence.current === request && selected.current === id;
    setBusy(true);
    setError("");
    setSettings(null);
    setGrants([]);
    try {
      const config = await api<Settings>(`/v1/scopes/${id}/modules`);
      if (!current()) return;
      setSettings(config);
      setCeiling(config.permissionCeiling);
      setRoots(config.selectedRoots);
      if (canEdit && config.actorPermissions.includes("owner")) {
        const list = await api<{ version: string; grants: Grant[] }>(`/v1/scopes/${id}/grants`);
        if (current()) setGrants(list.grants);
      }
    } catch (failure) {
      if (current()) setError((failure as Error).message);
    } finally {
      if (current()) setBusy(false);
    }
  }
  async function save(path: string, body: object) {
    if (!settings) return;
    const id = scopeId;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api(`/v1/scopes/${id}/${path}`, { ...body, expectedVersion: settings.version }, "PUT");
      if (isCurrent() && selected.current === id) {
        setNotice("Saved.");
        await load(id);
      }
    } catch (failure) {
      if (isCurrent() && selected.current === id) setError((failure as Error).message);
    } finally {
      if (isCurrent() && selected.current === id) setBusy(false);
    }
  }
  const owner = canEdit && !!settings?.actorPermissions.includes("owner");
  const configure = canEdit && (owner || !!settings?.actorPermissions.includes("configure"));
  const permissions = [
    ...new Set([...(settings?.registeredModules.flatMap((item) => item.permissions) ?? []), ...ceiling]),
  ].sort();
  const toggle = (values: string[], value: string, enabled: boolean) =>
    enabled ? [...new Set([...values, value])] : values.filter((item) => item !== value);
  return (
    <section className="panel desktop-panel">
      <div className="panel-heading">
        <h2>Management scopes</h2>
        <button type="button" disabled={busy || !scopeId} onClick={() => void load()}>
          Refresh
        </button>
      </div>
      <p>Scopes separate devices, optional features, permissions and operator access.</p>
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      <label>
        Scope
        <select
          value={scopeId}
          disabled={busy}
          onChange={(event) => {
            const id = event.target.value;
            selected.current = id;
            setScopeId(id);
            setSettings(null);
            setGrants([]);
            setNotice("");
            setError("");
            if (id) void load(id);
          }}
        >
          <option value="">Select scope</option>
          {scopes.map((scope) => (
            <option key={scope.id} value={scope.id}>
              {scope.name} ({scope.kind})
            </option>
          ))}
        </select>
      </label>
      {canEdit && (
        <details>
          <summary>Create scope</summary>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void (async () => {
                setBusy(true);
                setError("");
                creation.current ??= { id: crypto.randomUUID(), name: name.trim(), kind };
                const request = creation.current;
                try {
                  await api("/v1/scopes", request, "POST");
                  const list = await api<{ scopes: Scope[] }>("/v1/scopes");
                  if (!isCurrent()) return;
                  creation.current = null;
                  setScopes(list.scopes);
                  setName("");
                  selected.current = request.id;
                  setScopeId(request.id);
                  setNotice("Scope created. Optional features start disabled.");
                  await load(request.id);
                } catch (failure) {
                  if (isCurrent()) setError((failure as Error).message);
                } finally {
                  if (isCurrent()) setBusy(false);
                }
              })();
            }}
          >
            <label>
              Name
              <input
                value={name}
                required
                maxLength={120}
                disabled={busy || creation.current !== null}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <label>
              Purpose
              <select
                value={kind}
                disabled={busy || creation.current !== null}
                onChange={(event) => setKind(event.target.value as Scope["kind"])}
              >
                <option value="company">Company</option>
                <option value="personal">Personal</option>
              </select>
            </label>
            <button type="submit" disabled={busy || !name.trim()}>
              {creation.current ? "Resolve scope creation" : "Create scope"}
            </button>
          </form>
        </details>
      )}
      {settings && (
        <>
          <p>
            {settings.name} · {settings.kind} · version {settings.version}
          </p>
          <h3>Permission ceiling</h3>
          <p>
            Owners choose which capabilities this scope may use. Module selection must stay within this
            ceiling.
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void save("permissions", { permissions: ceiling });
            }}
          >
            {permissions.map((value) => (
              <label key={value}>
                <input
                  type="checkbox"
                  checked={ceiling.includes(value)}
                  disabled={busy || !owner}
                  onChange={(event) => setCeiling(toggle(ceiling, value, event.target.checked))}
                />
                {value}
              </label>
            ))}
            {owner && (
              <>
                <label>
                  Additional module permission
                  <input
                    value={customPermission}
                    onChange={(event) => setCustomPermission(event.target.value)}
                    disabled={busy}
                    pattern="[a-z][a-z0-9.-]{0,199}"
                  />
                </label>
                <button
                  type="button"
                  disabled={busy || !/^[a-z][a-z0-9.-]{0,199}$/.test(customPermission)}
                  onClick={() => {
                    setCeiling(toggle(ceiling, customPermission, true));
                    setCustomPermission("");
                  }}
                >
                  Add permission
                </button>
                <button type="submit" disabled={busy}>
                  Save permission ceiling
                </button>
              </>
            )}
          </form>
          <h3>Server features</h3>
          <p>
            Choose feature roots. Required dependencies are included automatically. Save their permissions
            first.
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void save("server-modules", { enabled: roots });
            }}
          >
            {settings.registeredModules.map((item) => (
              <label key={item.id}>
                <input
                  type="checkbox"
                  checked={roots.includes(item.id)}
                  disabled={busy || !configure}
                  onChange={(event) => setRoots(toggle(roots, item.id, event.target.checked))}
                />
                {item.id}
                {!roots.includes(item.id) &&
                settings.modules.some((entry) => entry.module_id === item.id && entry.state === "enabled")
                  ? " (required dependency)"
                  : ""}
                {item.dependencies.length ? ` · requires ${item.dependencies.join(", ")}` : ""}
              </label>
            ))}
            {configure && (
              <button type="submit" disabled={busy}>
                Save server features
              </button>
            )}
          </form>
          {owner && (
            <>
              <h3>Operator access</h3>
              <p>
                Use the exact sign-in issuer and subject. These grants apply within this scope; account roles
                still apply.
              </p>
              <table>
                <thead>
                  <tr>
                    <th>Issuer / subject</th>
                    <th>Permission</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {grants.map((item) => (
                    <tr key={JSON.stringify([item.issuer, item.subject, item.permission])}>
                      <td>
                        {item.issuer}
                        <br />
                        {item.subject}
                      </td>
                      <td>{item.permission}</td>
                      <td>{item.revoked_at ? "Revoked" : "Active"}</td>
                      <td>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() =>
                            void save("grants", {
                              issuer: item.issuer,
                              subject: item.subject,
                              permission: item.permission,
                              enabled: !!item.revoked_at,
                            })
                          }
                        >
                          {item.revoked_at ? "Restore grant" : "Revoke grant"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void save("grants", { issuer, subject, permission, enabled: true });
                }}
              >
                <label>
                  Issuer
                  <input
                    value={issuer}
                    required
                    maxLength={2048}
                    disabled={busy}
                    onChange={(event) => setIssuer(event.target.value)}
                  />
                </label>
                <label>
                  Subject
                  <input
                    value={subject}
                    required
                    maxLength={255}
                    disabled={busy}
                    onChange={(event) => setSubject(event.target.value)}
                  />
                </label>
                <label>
                  Permission
                  <select
                    value={permission}
                    disabled={busy}
                    onChange={(event) => setPermission(event.target.value)}
                  >
                    {access.map((item) => (
                      <option key={item}>{item}</option>
                    ))}
                  </select>
                </label>
                <button type="submit" disabled={busy}>
                  Add grant
                </button>
              </form>
            </>
          )}
        </>
      )}
    </section>
  );
}
