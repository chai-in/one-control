import { useEffect, useState } from "react";
import { EmaPanel } from "../../../modules/ema/console/EmaPanel.js";
import { FalconPanel } from "../../../modules/falcon/console/FalconPanel.js";
import { FalconDataPanel } from "../../../modules/falcon-sync/console/FalconDataPanel.js";

type Api = <T>(path: string, body?: unknown, method?: string) => Promise<T>;
type Scope = { id: string; name: string };
type ScopeSettings = {
  version: string;
  permissionCeiling: string[];
  selectedRoots: string[];
  modules: { module_id: string; state: string }[];
};
type Inventory = {
  resource: string;
  records: Record<string, unknown>[];
  total: number | null;
  collectedAt: string;
  next: { offset?: number; after?: string } | null;
};

function FalconInventoryPanel({
  api,
  scopeId,
  isCurrent,
}: {
  api: Api;
  scopeId: string;
  isCurrent: () => boolean;
}) {
  const [resource, setResource] = useState("hosts");
  const [filter, setFilter] = useState("");
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [host, setHost] = useState<unknown>(null);
  async function page(next?: Inventory["next"]) {
    setBusy(true);
    setError("");
    setHost(null);
    const query = new URLSearchParams({ scopeId, limit: "50" });
    if (filter) query.set("filter", filter);
    if (next?.offset !== undefined) query.set("offset", String(next.offset));
    if (next?.after) query.set("after", next.after);
    try {
      const result = await api<Inventory>(`/v1/integrations/falcon/inventory/${resource}?${query}`);
      if (isCurrent()) setInventory(result);
    } catch (failure) {
      if (isCurrent()) setError((failure as Error).message);
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  async function hostRead(aid: string, operation: string) {
    setBusy(true);
    setError("");
    try {
      const result = await api(
        `/v1/integrations/falcon/hosts/${encodeURIComponent(aid)}/${operation}?scopeId=${scopeId}`,
      );
      if (isCurrent()) setHost(result);
    } catch (failure) {
      if (isCurrent()) setError((failure as Error).message);
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  return (
    <section className="panel desktop-panel">
      <h2>Falcon inventory</h2>
      <div className="desktop-row">
        <label>
          Resource
          <select
            disabled={busy}
            value={resource}
            onChange={(event) => {
              setResource(event.target.value);
              setInventory(null);
              setHost(null);
              setFilter("");
            }}
          >
            {[
              "hosts",
              "assets",
              "applications",
              "groups",
              "vulnerabilities",
              "alerts",
              "incidents",
              "device-control",
              "prevention",
              "sensor-update",
            ].map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </label>
        <label>
          Optional Falcon query filter
          <input
            disabled={busy}
            value={filter}
            onChange={(event) => {
              setFilter(event.target.value);
              setInventory(null);
            }}
            placeholder="hostname:'computer-name'"
          />
        </label>
        <button type="button" disabled={busy} onClick={() => void page()}>
          Load first page
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
      {inventory && (
        <>
          <p>
            {inventory.records.length} records on this page
            {inventory.total === null ? "" : ` of ${inventory.total}`}. Collected{" "}
            {new Date(inventory.collectedAt).toLocaleString()}.
          </p>
          {inventory.records.map((row, index) => (
            <details key={String(row.device_id ?? row.id ?? row.composite_id ?? index)}>
              <summary>
                {String(
                  row.hostname ??
                    row.name ??
                    row.display_name ??
                    row.id ??
                    row.device_id ??
                    `Record ${index + 1}`,
                )}
                {row.status ? ` · ${String(row.status)}` : ""}
              </summary>
              <dl>
                {Object.entries(row)
                  .filter(([, value]) => ["string", "number", "boolean"].includes(typeof value))
                  .map(([key, value]) => (
                    <div key={key}>
                      <dt>{key.replaceAll("_", " ")}</dt>
                      <dd>{String(value)}</dd>
                    </div>
                  ))}
              </dl>
              {resource === "hosts" && typeof row.device_id === "string" && (
                <div className="desktop-row">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void hostRead(row.device_id as string, "detail")}
                  >
                    Host detail
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void hostRead(row.device_id as string, "assessment")}
                  >
                    Zero Trust assessment
                  </button>
                </div>
              )}
              <details>
                <summary>Source record</summary>
                <pre>{JSON.stringify(row, null, 2)}</pre>
              </details>
            </details>
          ))}
          {inventory.next && (
            <button type="button" disabled={busy} onClick={() => void page(inventory.next)}>
              Next page
            </button>
          )}
        </>
      )}
      {host !== null && (
        <details open>
          <summary>Host result</summary>
          <pre>{JSON.stringify(host, null, 2)}</pre>
        </details>
      )}
    </section>
  );
}

export function ScopedIntegrationPanel({
  kind,
  api,
  isCurrent,
  canEdit,
}: {
  kind: "falcon" | "ema";
  api: Api;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeId, setScopeId] = useState("");
  const [settings, setSettings] = useState<ScopeSettings | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    api<{ scopes: Scope[] }>("/v1/scopes")
      .then((result) => {
        if (live && isCurrent()) setScopes(result.scopes);
      })
      .catch((failure) => {
        if (live && isCurrent()) setError(failure.message);
      });
    return () => {
      live = false;
    };
  }, [api, isCurrent]);
  const enabled = settings?.modules.some((module) => module.module_id === kind && module.state === "enabled");
  async function select(id: string) {
    setScopeId(id);
    setSettings(null);
    setError("");
    if (!id) return;
    setBusy(true);
    try {
      const result = await api<ScopeSettings>(`/v1/scopes/${id}/modules`);
      if (isCurrent()) setSettings(result);
    } catch (failure) {
      if (isCurrent()) setError((failure as Error).message);
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  async function enable() {
    if (!settings) return;
    setBusy(true);
    setError("");
    try {
      let expectedVersion = settings.version;
      if (!settings.permissionCeiling.includes(`${kind}.read`))
        expectedVersion = (
          await api<{ version: string }>(
            `/v1/scopes/${scopeId}/permissions`,
            { expectedVersion, permissions: [...settings.permissionCeiling, `${kind}.read`] },
            "PUT",
          )
        ).version;
      await api(
        `/v1/scopes/${scopeId}/server-modules`,
        {
          expectedVersion,
          enabled: [...settings.selectedRoots.filter((id) => id !== kind), kind],
        },
        "PUT",
      );
      if (isCurrent()) await select(scopeId);
    } catch (failure) {
      if (isCurrent()) setError((failure as Error).message);
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  return (
    <>
      <section className="panel desktop-panel">
        <label>
          Management scope
          <select disabled={busy} value={scopeId} onChange={(event) => void select(event.target.value)}>
            <option value="">Select a scope</option>
            {scopes.map((scope) => (
              <option key={scope.id} value={scope.id}>
                {scope.name}
              </option>
            ))}
          </select>
        </label>
        {error && <p role="alert">{error} Refresh the scope before retrying.</p>}
        {settings && !enabled && (
          <p>
            This integration is disabled.{" "}
            {canEdit && (
              <button type="button" disabled={busy} onClick={() => void enable()}>
                Enable {kind === "falcon" ? "Falcon" : "Intel EMA"} reads
              </button>
            )}
          </p>
        )}
        <p>Server configuration must bind this integration to the selected scope.</p>
      </section>
      {enabled &&
        (kind === "falcon" ? (
          <>
            <FalconPanel
              key={`capabilities:${scopeId}`}
              isCurrent={isCurrent}
              readCapabilities={() => api(`/v1/integrations/falcon/capabilities?scopeId=${scopeId}`)}
            />
            <FalconInventoryPanel
              key={`inventory:${scopeId}`}
              api={api}
              scopeId={scopeId}
              isCurrent={isCurrent}
            />
            <FalconDataPanel
              key={`data:${scopeId}`}
              api={api}
              scopeId={scopeId}
              isCurrent={isCurrent}
              canEdit={canEdit}
            />
          </>
        ) : (
          <EmaPanel
            key={scopeId}
            isCurrent={isCurrent}
            readInventory={() => api(`/v1/integrations/ema/endpoints?scopeId=${scopeId}`)}
          />
        ))}
    </>
  );
}
