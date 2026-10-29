import type { Device, Job } from "@one-control/protocol";
import { Activity, Download, Monitor, Search, ShieldCheck, ShieldOff } from "lucide-react";
import { useState } from "react";
import { DeviceHardware } from "../../../modules/inventory/console/DeviceHardware.js";
import { StateBadge } from "../../../modules/native-dispatch/console/OperationDetails.js";
import { Dialog } from "./Dialog.js";
import { coverage } from "./device-health.js";
import {
  applications,
  connection,
  date,
  labels,
  type OperationDraft,
  relativeTime,
  text,
} from "./view-model.js";

export function DeviceDetails({
  device,
  jobs,
  jobsAvailable = true,
  operator,
  busy,
  close,
  createOperation,
  openJob,
  changeRing,
  revoke,
  error,
  allowBroaderRings,
}: {
  device: Device;
  jobs: Job[];
  jobsAvailable?: boolean;
  operator: boolean;
  busy: boolean;
  close: () => void;
  createOperation: (draft: OperationDraft) => void;
  openJob: (job: Job) => void;
  changeRing: (ring: Device["ring"]) => Promise<void>;
  revoke: () => Promise<void>;
  error: string;
  allowBroaderRings: boolean;
}) {
  const [appSearch, setAppSearch] = useState("");
  const [ring, setRing] = useState(device.ring);
  const [showRevoke, setShowRevoke] = useState(false);
  const [revokeName, setRevokeName] = useState("");
  const status = connection(device);
  const inventory = device.inventory;
  const collected = coverage(inventory);
  const deviceJobs = jobs.filter((job) => job.device_id === device.id);
  const unresolved = deviceJobs.filter((job) => job.state === "indeterminate");
  const unfinished = deviceJobs.some((job) =>
    ["awaiting_approval", "queued", "leased", "indeterminate"].includes(job.state),
  );
  const apps = applications(inventory);
  const filtered = apps.filter((app) =>
    `${app.name} ${app.publisher} ${app.version}`.toLowerCase().includes(appSearch.toLowerCase()),
  );
  return (
    <Dialog title={device.hostname} close={close} closeLabel="Close details" wide busy={busy} error={error}>
      <div className="detail-meta">
        <span className={`status ${status.tone}`}>{status.label}</span>
        <span className="ring">{device.ring}</span>
        {device.management_scope_name && <span>{device.management_scope_name}</span>}
        <span title={date(device.last_seen_at)}>Last seen {relativeTime(device.last_seen_at)}</span>
      </div>
      {unresolved.length > 0 && (
        <div className="notice warning">
          <ShieldOff size={19} />
          <div>
            <strong>Updates are paused for verification</strong>
            <p>
              {unresolved.length} uncertain {unresolved.length === 1 ? "operation needs" : "operations need"}{" "}
              IT reconciliation before this computer can receive further work.
            </p>
            <button
              className="text-button"
              type="button"
              onClick={() => {
                const job = unresolved[0];
                if (job) openJob(job);
              }}
            >
              Review the uncertain operation
            </button>
          </div>
        </div>
      )}
      {operator && !device.revoked_at && (
        <div className="quick-actions">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => createOperation({ kind: "inventory.scan", deviceIds: [device.id] })}
          >
            <Activity size={15} />
            Refresh inventory
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy}
            onClick={() => createOperation({ kind: "windows.scan", deviceIds: [device.id] })}
          >
            <Download size={15} />
            Scan Windows updates
          </button>
        </div>
      )}
      <div className="device-health-grid">
        <div>
          <Monitor size={19} />
          <span>Agent version</span>
          <strong>{text(inventory?.agentVersion)}</strong>
        </div>
        <div>
          <ShieldCheck size={19} />
          <span>Independent recovery</span>
          <strong>
            {inventory?.agentRecoveryReady === true
              ? "Ready"
              : inventory?.agentRecoveryReady === false
                ? "Not running"
                : "Not reported"}
          </strong>
        </div>
        <div>
          <Download size={19} />
          <span>Restart status</span>
          <strong>
            {inventory?.rebootPending === true
              ? "Restart needed"
              : inventory?.rebootPending === false
                ? "No restart reported"
                : "Not reported"}
          </strong>
        </div>
      </div>
      <dl className="facts two-columns">
        <div>
          <dt>Operating system</dt>
          <dd>{text(inventory?.osVersion)}</dd>
        </div>
        <div>
          <dt>Windows release / build</dt>
          <dd>
            {text(inventory?.displayVersion, "—")} / {text(inventory?.build, "—")}
          </dd>
        </div>
        <div>
          <dt>Architecture</dt>
          <dd>{text(inventory?.architecture)}</dd>
        </div>
        <div>
          <dt>Inventory collected</dt>
          <dd>{date(typeof inventory?.collectedAt === "string" ? inventory.collectedAt : null)}</dd>
        </div>
        <div>
          <dt>User session</dt>
          <dd>
            {inventory?.interactiveSessionAvailable === true
              ? "Available for user-scoped updates"
              : inventory?.interactiveSessionAvailable === false
                ? "No interactive session"
                : "Not reported"}
          </dd>
        </div>
      </dl>
      {collected.partial && (
        <div className="notice warning">
          <ShieldOff size={18} />
          <div>
            <strong>Partial inventory</strong>
            <p>
              Some observations could not be read or reached a collection limit. Review{" "}
              {collected.sections.join(", ") || "inventory"} coverage before planning changes.
            </p>
          </div>
        </div>
      )}
      <DeviceHardware inventory={inventory} />
      <div className="section-heading">
        <h3>
          Installed applications <span className="count-pill">{apps.length}</span>
        </h3>
        <div className="search">
          <Search size={15} />
          <input
            aria-label="Search installed applications"
            value={appSearch}
            onChange={(event) => setAppSearch(event.target.value)}
            placeholder="Find an application"
          />
        </div>
      </div>
      <p className="inventory-scope">
        {collected.machineApplications
          ? "Machine registry applications (32-bit and 64-bit). User applications and Store packages are outside this list."
          : "Application coverage was not reported by this agent."}
      </p>
      {filtered.length ? (
        <div className="table-wrap application-table">
          <table>
            <thead>
              <tr>
                <th>Application</th>
                <th>Version</th>
                <th>Publisher</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((app) => (
                <tr key={JSON.stringify([app.name, app.version, app.publisher])}>
                  <td>{app.name}</td>
                  <td>{app.version}</td>
                  <td>{app.publisher}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-copy">
          {apps.length
            ? "No applications match your search."
            : "No application records have been reported. Refresh inventory to collect them."}
        </p>
      )}
      <h3 className="section-title">Recent operations</h3>
      {deviceJobs.length ? (
        <div className="device-job-list">
          {deviceJobs.slice(0, 8).map((job) => (
            <button type="button" key={job.id} onClick={() => openJob(job)}>
              <div>
                <strong>{labels[job.kind]}</strong>
                <small>{date(job.created_at)}</small>
              </div>
              <StateBadge state={job.state} />
            </button>
          ))}
        </div>
      ) : !jobsAvailable ? (
        <p className="empty-copy">Operation history is unavailable.</p>
      ) : (
        <p className="empty-copy">This computer has no recorded operations.</p>
      )}
      {operator && !device.revoked_at && (
        <section className="device-management">
          <h3>Device management</h3>
          <form
            className="ring-form"
            onSubmit={(event) => {
              event.preventDefault();
              void changeRing(ring);
            }}
          >
            <div>
              <label htmlFor="device-ring">Rollout ring</label>
              <select
                id="device-ring"
                aria-label="Change rollout ring"
                value={ring}
                disabled={busy || unfinished}
                onChange={(event) => setRing(event.target.value as Device["ring"])}
              >
                {!allowBroaderRings && device.ring !== "canary" && (
                  <option value={device.ring} disabled>
                    {device.ring} — outside POC
                  </option>
                )}
                {(allowBroaderRings ? ["canary", "pilot", "broad"] : ["canary"]).map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </div>
            <button type="submit" className="secondary" disabled={busy || unfinished || ring === device.ring}>
              Save ring
            </button>
          </form>
          {unfinished && (
            <p className="subtle">Finish or reconcile outstanding operations before changing the ring.</p>
          )}
          {!showRevoke ? (
            <button
              className="text-button danger-text"
              type="button"
              disabled={busy}
              onClick={() => setShowRevoke(true)}
            >
              Revoke this computer
            </button>
          ) : (
            <div className="revoke-review">
              <p>
                Revoking access cancels pending jobs and invalidates this computer’s credentials. An active
                installation becomes uncertain and requires verification.
              </p>
              <label htmlFor="revoke-name">Type {device.hostname} to confirm</label>
              <input
                id="revoke-name"
                value={revokeName}
                onChange={(event) => setRevokeName(event.target.value)}
                autoComplete="off"
              />
              <button
                type="button"
                className="danger-button"
                disabled={busy || revokeName !== device.hostname}
                onClick={() => void revoke()}
              >
                Revoke device access
              </button>
            </div>
          )}
        </section>
      )}
      <details className="technical-record">
        <summary>Technical inventory record</summary>
        <pre>{JSON.stringify(device, null, 2)}</pre>
      </details>
    </Dialog>
  );
}
