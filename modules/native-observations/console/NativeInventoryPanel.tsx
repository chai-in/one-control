import { useState } from "react";
import { type ScopedApi, useScopedModule } from "../../../apps/console/src/use-scoped-module.js";
import "../../desktop-policies/console/desktop.css";

type Observation<T> = { status: string; value?: T; reason?: string };
type Device = {
  enrollment_id: string;
  device_id: string;
  hostname: string;
  platform: string;
  revoked_at: string | null;
  last_seen_at: string | null;
  inventory_received_at: string | null;
  last_sequence: string | null;
  inventory: null | {
    moduleVersion: string;
    report: {
      collectedAt: string;
      hostname: Observation<string>;
      osVersion: Observation<{ major: number; minor: number; build: number }>;
      nativeArchitecture: Observation<string>;
      processArchitecture: Observation<string>;
      cpu: Observation<{ activeLogicalProcessors: number; activeProcessorGroups: number }>;
      memory: Observation<{ totalBytes: number; availableBytes: number }>;
      elapsedSinceStartMilliseconds: Observation<number>;
    };
  };
};
function value<T>(item: Observation<T>, format: (value: T) => string) {
  return item.status === "available" && item.value !== undefined
    ? format(item.value)
    : `${item.status}: ${item.reason?.replaceAll("_", " ") ?? "not reported"}`;
}
const date = (at: string | null) => (at ? new Date(at).toLocaleString() : "No report");
export function NativeInventoryPanel({
  api,
  isCurrent,
  canEdit,
}: {
  api: ScopedApi;
  isCurrent: () => boolean;
  canEdit: boolean;
}) {
  const module = useScopedModule<{ version: string; devices: Device[] }>(
    api,
    isCurrent,
    "native-observations",
    "",
    "native-observations",
  );
  const [selected, setSelected] = useState("");
  const device = module.data?.devices.find((row) => row.enrollment_id === selected),
    report = device?.inventory?.report;
  return (
    <section className="panel desktop-panel">
      <div className="panel-heading">
        <h2>Native inventory</h2>
        <button type="button" disabled={module.busy || !module.scopeId} onClick={() => void module.load()}>
          Refresh
        </button>
      </div>
      <label>
        Management scope
        <select
          value={module.scopeId}
          disabled={module.busy}
          onChange={(event) => {
            setSelected("");
            module.select(event.target.value);
          }}
        >
          <option value="">Select scope</option>
          {module.scopes.map((scope) => (
            <option key={scope.id} value={scope.id}>
              {scope.name}
            </option>
          ))}
        </select>
      </label>
      {module.error && <p role="alert">{module.error}</p>}
      {module.settings && !module.data && canEdit && (
        <button type="button" disabled={module.busy} onClick={() => void module.enable(true)}>
          Enable native reporting
        </button>
      )}
      {module.data && (
        <>
          <p>
            Reports are tied to the enrollment that sent them. Device observations are self-reported;
            collection and receipt times are shown separately.
          </p>
          {canEdit && (
            <button type="button" disabled={module.busy} onClick={() => void module.enable(false)}>
              Disable reporting
            </button>
          )}
          <table>
            <thead>
              <tr>
                <th>Computer</th>
                <th>Platform</th>
                <th>Enrollment</th>
                <th>Last check-in</th>
                <th>Inventory received</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {module.data.devices.map((row) => (
                <tr key={row.enrollment_id}>
                  <td>{row.hostname}</td>
                  <td>{row.platform}</td>
                  <td>{row.revoked_at ? "Revoked" : "Active"}</td>
                  <td>{date(row.last_seen_at)}</td>
                  <td>{date(row.inventory_received_at)}</td>
                  <td>
                    <button type="button" onClick={() => setSelected(row.enrollment_id)}>
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!module.data.devices.length && <p>No native enrollments in this scope.</p>}
          {device && (
            <>
              <h3>{device.hostname}</h3>
              <dl>
                <dt>Enrollment</dt>
                <dd>{device.enrollment_id}</dd>
                <dt>Last receipt sequence</dt>
                <dd>{device.last_sequence ?? "None"}</dd>
              </dl>
              {report ? (
                <dl>
                  <dt>Collected</dt>
                  <dd>{date(report.collectedAt)}</dd>
                  <dt>Received</dt>
                  <dd>{date(device.inventory_received_at)}</dd>
                  <dt>Reported hostname</dt>
                  <dd>{value(report.hostname, String)}</dd>
                  <dt>Windows version</dt>
                  <dd>{value(report.osVersion, (v) => `${v.major}.${v.minor}, build ${v.build}`)}</dd>
                  <dt>Native architecture</dt>
                  <dd>{value(report.nativeArchitecture, String)}</dd>
                  <dt>Collector architecture</dt>
                  <dd>{value(report.processArchitecture, String)}</dd>
                  <dt>CPU</dt>
                  <dd>
                    {value(
                      report.cpu,
                      (v) =>
                        `${v.activeLogicalProcessors} logical processors in ${v.activeProcessorGroups} groups`,
                    )}
                  </dd>
                  <dt>Memory</dt>
                  <dd>
                    {value(
                      report.memory,
                      (v) =>
                        `${(v.totalBytes / 1073741824).toFixed(1)} GiB total, ${(v.availableBytes / 1073741824).toFixed(1)} GiB available`,
                    )}
                  </dd>
                  <dt>Elapsed since collector start</dt>
                  <dd>
                    {value(report.elapsedSinceStartMilliseconds, (v) => `${Math.floor(v / 1000)} seconds`)}
                  </dd>
                </dl>
              ) : (
                <p>
                  No inventory received for this enrollment. Collection requires the inventory module to be
                  selected and permitted.
                </p>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}
