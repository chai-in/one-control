import { useState } from "react";
import type { ScopedApi } from "../../../apps/console/src/use-scoped-module.js";

type Sync = {
  version: string;
  resources: string[];
  scheduledIntervalSeconds: number;
  state: {
    resource: string;
    status: string;
    count: number;
    error_code: string | null;
    completed_at: string | null;
    updated_at: string;
    filter: string | null;
  }[];
};
type Cached = {
  resource: string;
  offset: number;
  limit: number;
  state: { status: string; completed_at: string | null; filter: string | null } | null;
  records: { source_id: string; payload: Record<string, unknown>; observed_at: string; present: boolean }[];
};
type Event = {
  event_id: string;
  event_type: string;
  aid: string | null;
  payload: Record<string, unknown>;
  occurred_at: string;
  received_at: string;
};
export function FalconDataPanel({
  api,
  scopeId,
  isCurrent,
  canEdit,
}: {
  api: ScopedApi;
  scopeId: string;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const [sync, setSync] = useState<Sync | null>(null);
  const [cached, setCached] = useState<Cached | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [resource, setResource] = useState("hosts");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const base = `/v1/scopes/${scopeId}`;
  async function action(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await work();
    } catch (failure) {
      if (isCurrent()) setError((failure as Error).message);
    } finally {
      if (isCurrent()) setBusy(false);
    }
  }
  async function status() {
    const result = await api<Sync>(`${base}/falcon-sync`);
    if (isCurrent()) setSync(result);
  }
  async function enable(moduleId: "falcon-sync" | "falcon-events", enabled: boolean) {
    const config = await api<{
      version: string;
      permissionCeiling: string[];
      selectedRoots: string[];
      modules: { module_id: string; state: string }[];
    }>(`${base}/modules`);
    let expectedVersion = config.version;
    const permission = moduleId === "falcon-sync" ? "falcon.sync" : "falcon.events";
    if (enabled && !config.permissionCeiling.includes(permission))
      expectedVersion = (
        await api<{ version: string }>(
          `${base}/permissions`,
          { expectedVersion, permissions: [...config.permissionCeiling, permission] },
          "PUT",
        )
      ).version;
    const modules = config.selectedRoots.filter((id) => id !== moduleId);
    if (enabled) modules.push(moduleId);
    await api(`${base}/server-modules`, { expectedVersion, enabled: modules }, "PUT");
    if (isCurrent()) {
      setNotice(
        `${moduleId === "falcon-sync" ? "Inventory sync" : "Event ingestion"} ${enabled ? "enabled" : "disabled"}.`,
      );
      if (!enabled && moduleId === "falcon-sync") {
        setSync(null);
        setCached(null);
      }
      if (!enabled && moduleId === "falcon-events") setEvents([]);
    }
  }
  async function page(offset = 0) {
    const result = await api<Cached>(`${base}/falcon-cache/${resource}?offset=${offset}`);
    if (isCurrent()) setCached(result);
  }
  return (
    <section className="panel desktop-panel">
      <h2>Inventory sync and events</h2>
      <p>
        These optional modules retain Falcon observations separately from native device state. Cached records
        show when they were collected and whether the last completed scan still contained them.
      </p>
      {error && <p role="alert">{error} Refresh state before retrying a change.</p>}
      {notice && <p role="status">{notice}</p>}
      {canEdit && (
        <div className="desktop-row">
          {(["falcon-sync", "falcon-events"] as const).map((moduleId) => (
            <div className="desktop-row" key={moduleId}>
              <button type="button" disabled={busy} onClick={() => void action(() => enable(moduleId, true))}>
                Enable {moduleId === "falcon-sync" ? "inventory sync" : "events"}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void action(() => enable(moduleId, false))}
              >
                Disable {moduleId === "falcon-sync" ? "inventory sync" : "events"}
              </button>
            </div>
          ))}
        </div>
      )}
      <button type="button" disabled={busy} onClick={() => void action(status)}>
        Load sync status
      </button>
      {sync && (
        <>
          <p>
            {sync.scheduledIntervalSeconds
              ? `Scheduled refresh interval: ${sync.scheduledIntervalSeconds} seconds.`
              : "Scheduled refresh is off. Sync pages run only when requested here."}
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>Status</th>
                  <th>Records in pass</th>
                  <th>Completed</th>
                  <th>Last error</th>
                </tr>
              </thead>
              <tbody>
                {sync.state.map((row) => (
                  <tr key={row.resource}>
                    <td>{row.resource}</td>
                    <td>{row.status}</td>
                    <td>{row.count}</td>
                    <td>{row.completed_at ? new Date(row.completed_at).toLocaleString() : "Incomplete"}</td>
                    <td>{row.error_code ?? "None"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="desktop-row">
            <label>
              Resource
              <select
                disabled={busy}
                value={resource}
                onChange={(event) => {
                  setResource(event.target.value);
                  setCached(null);
                  setFilter("");
                }}
              >
                {sync.resources.map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </label>
            <label>
              Filter for new scan
              <input disabled={busy} value={filter} onChange={(event) => setFilter(event.target.value)} />
            </label>
            {canEdit && (
              <>
                {[false, true].map((restart) => (
                  <button
                    type="button"
                    key={String(restart)}
                    disabled={busy}
                    onClick={() =>
                      void action(async () => {
                        const result = await api<{ result: { status: string; error?: string } }>(
                          `${base}/falcon-sync/${resource}`,
                          {
                            expectedVersion: sync.version,
                            restart,
                            ...(restart && filter ? { filter } : {}),
                          },
                        );
                        if (isCurrent())
                          setNotice(
                            result.result.status === "error"
                              ? `Sync failed: ${result.result.error}. Previous cache remains available.`
                              : `Sync page saved: ${result.result.status}.`,
                          );
                        await status();
                      })
                    }
                  >
                    {restart ? "Start new scan — first page" : "Continue scan — next page"}
                  </button>
                ))}
              </>
            )}
            <button type="button" disabled={busy} onClick={() => void action(() => page())}>
              Read cached records
            </button>
          </div>
        </>
      )}
      {cached && (
        <>
          <p>
            Cache pass: {cached.state?.status ?? "No scan"}
            {cached.state?.filter ? ` · ${cached.state.filter}` : ""}.{" "}
            {cached.state?.completed_at
              ? `Completed ${new Date(cached.state.completed_at).toLocaleString()}.`
              : "A full scan has not completed."}
          </p>
          {cached.records.map((row) => (
            <details key={row.source_id}>
              <summary>
                {String(
                  row.payload.hostname ?? row.payload.name ?? row.payload.display_name ?? row.source_id,
                )}{" "}
                · {row.present ? "present in latest observation" : "absent from last complete scan"} ·{" "}
                {new Date(row.observed_at).toLocaleString()}
              </summary>
              <pre>{JSON.stringify(row.payload, null, 2)}</pre>
            </details>
          ))}
          <div className="desktop-row">
            <button
              type="button"
              disabled={busy || cached.offset === 0}
              onClick={() => void action(() => page(Math.max(0, cached.offset - cached.limit)))}
            >
              Previous cache page
            </button>
            <button
              type="button"
              disabled={busy || cached.records.length < cached.limit}
              onClick={() => void action(() => page(cached.offset + cached.limit))}
            >
              Next cache page
            </button>
          </div>
        </>
      )}
      <h3>Falcon events</h3>
      <p>
        The webhook uses a separately configured signing secret. Enabling this module does not configure the
        external Fusion workflow.
      </p>
      <button
        type="button"
        disabled={busy}
        onClick={() =>
          void action(async () => {
            const result = await api<{ events: Event[] }>(`${base}/falcon-events`);
            if (isCurrent()) setEvents(result.events);
          })
        }
      >
        Load recent events
      </button>
      {events.map((event) => (
        <details key={event.event_id}>
          <summary>
            {event.event_type} · {event.aid ?? "No host ID"} · {new Date(event.occurred_at).toLocaleString()}
          </summary>
          <p>Received {new Date(event.received_at).toLocaleString()}</p>
          <pre>{JSON.stringify(event.payload, null, 2)}</pre>
        </details>
      ))}
    </section>
  );
}
