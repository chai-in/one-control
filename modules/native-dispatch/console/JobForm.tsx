import { type Command, createJobSchema, type Device, type Job } from "@one-control/protocol";
import { ChevronRight, Info, Lock, Search } from "lucide-react";
import { type FormEvent, useRef, useState } from "react";
import {
  commonUpdates,
  connection,
  labels,
  type OperationDraft,
  type Release,
} from "../../../apps/console/src/view-model.js";
import { sessionChoices } from "../../user-session-host/console/session-choices.js";

const descriptions: Record<Command["kind"], string> = {
  "sessions.list": "Read signed-in console and RDP sessions. No user task is started by this operation.",
  "applications.check":
    "Check WinGet availability in the explicitly selected user session. This does not install or upgrade an application.",
  "applications.upgrade":
    "Upgrade one exact WinGet package/version for the selected user. Requires independent approval; no elevation or automatic reboot is permitted.",
  "inventory.scan":
    "Collect the computer’s current agent, Windows and application inventory. This does not install software.",
  "windows.scan":
    "Find applicable Windows software updates using the computer’s existing update configuration.",
  "windows.install":
    "Install selected update IDs and revisions from recent scans. A separate approver is required.",
  "indexing.status":
    "Read the Search service, startup setting and actual catalog activity without changing indexing.",
  "indexing.enable":
    "Set the approved startup mode and start Windows Search, preserving its catalog and location rules.",
  "indexing.disable":
    "Disable startup and stop Windows Search. Indexed search will be unavailable; catalog and location rules are preserved.",
  "indexing.pause":
    "Stop the Search service without changing its startup setting. This is a service-stop fallback, not a true indexing pause; indexed queries are unavailable until it starts again.",
  "indexing.resume":
    "Start the Search service using its existing startup setting. A disabled service must first be enabled.",
  "winget.upgrade": "Upgrade an exact WinGet package to a pinned version in the signed-in user’s session.",
  "store.upgrade":
    "Request an update for one supported Microsoft Store product in the signed-in user’s session.",
  "package.install":
    "Install an approved, signed MSI release. Agent releases require independent recovery to be ready.",
};
const localTime = (time: number) => {
  const value = new Date(time);
  value.setMinutes(value.getMinutes() - value.getTimezoneOffset());
  return value.toISOString().slice(0, 16);
};

export function JobForm({
  devices,
  jobs,
  releases,
  busy,
  draft,
  onSubmit,
  allowBroaderRings,
}: {
  devices: Device[];
  jobs: Job[];
  releases: Release[];
  busy: boolean;
  draft: OperationDraft | null;
  onSubmit: (input: unknown, idempotencyKey: string) => Promise<void>;
  allowBroaderRings: boolean;
}) {
  const requests = useRef(new Map<string, string>());
  const initialDevice = devices.find((device) => draft?.deviceIds.includes(device.id));
  const [kind, setKind] = useState<Command["kind"]>(draft?.kind ?? "inventory.scan");
  const [ring, setRing] = useState(allowBroaderRings ? (initialDevice?.ring ?? "canary") : "canary");
  const [selected, setSelected] = useState<string[]>(
    (draft?.deviceIds ?? []).filter((id) =>
      devices.some((device) => device.id === id && (allowBroaderRings || device.ring === "canary")),
    ),
  );
  const [updates, setUpdates] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [formError, setFormError] = useState("");
  const [sessionKey, setSessionKey] = useState("");
  const sessions = sessionChoices(jobs, selected);
  const targetSession = sessions.find((session) => session.key === sessionKey)?.target;
  const applicable = commonUpdates(jobs, selected);
  const chosenUpdates = applicable.updates.filter((update) =>
    updates.includes(`${update.id}:${update.revision}`),
  );
  const targets = devices.filter((device) => device.ring === ring && !device.revoked_at);
  const shownTargets = targets.filter((device) =>
    device.hostname.toLowerCase().includes(search.toLowerCase()),
  );
  const mutating = ![
    "inventory.scan",
    "windows.scan",
    "indexing.status",
    "sessions.list",
    "applications.check",
  ].includes(kind);
  function changeTargets(ids: string[]) {
    setSelected(ids);
    setUpdates([]);
    setSessionKey("");
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError("");
    try {
      const data = new FormData(event.currentTarget);
      let command: unknown = { kind };
      if (kind === "applications.check") command = { kind, session: targetSession };
      if (kind === "applications.upgrade")
        command = {
          kind,
          session: targetSession,
          packageId: String(data.get("packageId")).trim(),
          version: String(data.get("version")).trim(),
        };
      if (kind === "indexing.enable") command = { kind, startup: String(data.get("startup")) };
      if (kind === "windows.install")
        command = { kind, updates: chosenUpdates.map(({ id, revision }) => ({ id, revision })) };
      if (kind === "winget.upgrade")
        command = {
          kind,
          packageId: String(data.get("packageId")).trim(),
          version: String(data.get("version")).trim(),
        };
      if (kind === "store.upgrade") command = { kind, packageId: String(data.get("packageId")).trim() };
      if (kind === "package.install") command = { kind, releaseId: String(data.get("releaseId")) };
      const payload = {
        targets: selected,
        ring,
        command,
        startsAt: new Date(String(data.get("startsAt"))).toISOString(),
        endsAt: new Date(String(data.get("endsAt"))).toISOString(),
      };
      const parsed = createJobSchema.safeParse(payload);
      if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? "Check the operation details.");
      const fingerprint = JSON.stringify(parsed.data);
      const key = requests.current.get(fingerprint) ?? crypto.randomUUID();
      requests.current.set(fingerprint, key);
      await onSubmit(parsed.data, key);
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Check the operation details.");
    }
  }
  return (
    <form onSubmit={(event) => void submit(event)}>
      <label htmlFor="kind">Operation</label>
      <select
        id="kind"
        value={kind}
        onChange={(event) => {
          setKind(event.target.value as Command["kind"]);
          setUpdates([]);
        }}
      >
        {Object.entries(labels).map(([id, label]) => (
          <option key={id} value={id}>
            {label}
          </option>
        ))}
      </select>
      <p className="field-help">{descriptions[kind]}</p>
      {kind === "indexing.enable" && (
        <label>
          Search startup mode
          <select name="startup" defaultValue="automatic-delayed">
            <option value="automatic-delayed">Automatic (delayed)</option>
            <option value="automatic">Automatic</option>
            <option value="manual">Manual</option>
          </select>
        </label>
      )}
      <label htmlFor="ring">Rollout ring</label>
      <select
        id="ring"
        value={ring}
        onChange={(event) => {
          setRing(event.target.value as Device["ring"]);
          changeTargets([]);
        }}
      >
        {(allowBroaderRings ? ["canary", "pilot", "broad"] : ["canary"]).map((value) => (
          <option key={value}>{value}</option>
        ))}
      </select>
      <div className="target-heading">
        <label htmlFor="target-search">
          Target computers <span className="count-pill">{selected.length} selected</span>
        </label>
        {targets.length > 1 && (
          <button
            type="button"
            className="text-button"
            onClick={() =>
              changeTargets(selected.length === targets.length ? [] : targets.map((device) => device.id))
            }
          >
            {selected.length === targets.length ? "Clear selection" : "Select this ring"}
          </button>
        )}
      </div>
      {targets.length > 5 && (
        <div className="search">
          <Search size={15} />
          <input
            id="target-search"
            aria-label="Find target computers"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Find a computer"
          />
        </div>
      )}
      <fieldset className="target-list">
        <legend>Computers in the {ring} ring</legend>
        {shownTargets.map((device) => {
          const status = connection(device);
          return (
            <label className="checkbox" key={device.id}>
              <input
                type="checkbox"
                aria-label={device.hostname}
                checked={selected.includes(device.id)}
                onChange={(event) =>
                  changeTargets(
                    event.target.checked
                      ? [...selected, device.id]
                      : selected.filter((id) => id !== device.id),
                  )
                }
              />
              <span>{device.hostname}</span>
              <span className={`status ${status.tone}`}>{status.label}</span>
            </label>
          );
        })}
        {!shownTargets.length && (
          <p className="subtle">
            {targets.length ? "No computers match this search." : "No computers are enrolled in this ring."}
          </p>
        )}
      </fieldset>
      {(kind === "applications.check" || kind === "applications.upgrade") && (
        <>
          <label htmlFor="selected-session">User session</label>
          <select
            id="selected-session"
            required
            value={sessionKey}
            onChange={(event) => setSessionKey(event.target.value)}
          >
            <option value="">Select a verified user session</option>
            {sessions.map((session) => (
              <option key={session.key} value={session.key}>
                {session.label}
              </option>
            ))}
          </select>
          {!sessions.length && (
            <p>
              Choose one computer and refresh its signed-in sessions first. Session results expire after five
              minutes.{" "}
              <button type="button" className="text-button" onClick={() => setKind("sessions.list")}>
                Read signed-in sessions
              </button>
            </p>
          )}
        </>
      )}
      {selected.some(
        (id) => devices.find((device) => device.id === id)?.inventory?.interactiveSessionAvailable === false,
      ) &&
        (kind === "winget.upgrade" || kind === "store.upgrade") && (
          <div className="notice warning">
            <Info size={17} />
            <p>
              A selected computer reports no interactive user session. User-scoped updates require a suitable
              signed-in user.
            </p>
          </div>
        )}
      {kind === "windows.install" && (
        <div className="update-picker">
          <h3>Choose updates from completed scans</h3>
          <p className="field-help">
            Scans must be less than 24 hours old. For several computers, only identical IDs and revisions
            reported by every target are offered. The agent rechecks applicability before installation.
          </p>
          {applicable.missing.length > 0 ? (
            <div className="notice warning">
              <Info size={17} />
              <div>
                <strong>A recent scan is needed</strong>
                <p>
                  {applicable.missing
                    .map((id) => devices.find((device) => device.id === id)?.hostname ?? id)
                    .join(", ")}
                </p>
                <button className="small-button" type="button" onClick={() => setKind("windows.scan")}>
                  Prepare a scan for these computers
                </button>
              </div>
            </div>
          ) : applicable.updates.length ? (
            <fieldset>
              <legend>Applicable updates · {chosenUpdates.length} selected</legend>
              {applicable.updates.map((update) => {
                const key = `${update.id}:${update.revision}`;
                return (
                  <label className="checkbox update-choice" key={key}>
                    <input
                      type="checkbox"
                      checked={updates.includes(key)}
                      onChange={(event) =>
                        setUpdates(
                          event.target.checked ? [...updates, key] : updates.filter((value) => value !== key),
                        )
                      }
                    />
                    <span>
                      {update.title}
                      <small>Revision {update.revision}</small>
                    </span>
                  </label>
                );
              })}
            </fieldset>
          ) : (
            <p className="empty-copy">
              {selected.length
                ? "No common applicable updates were reported. Select one computer to review its own scan."
                : "Select a computer to see its scanned updates."}
            </p>
          )}
        </div>
      )}
      {(kind === "winget.upgrade" || kind === "store.upgrade" || kind === "applications.upgrade") && (
        <>
          <label htmlFor="packageId">
            {kind === "store.upgrade" ? "Store product ID" : "WinGet package ID"}
          </label>
          <input
            id="packageId"
            name="packageId"
            required
            placeholder={kind === "store.upgrade" ? "9WZDNCRFHVN5" : "Microsoft.PowerToys"}
          />
          {kind === "store.upgrade" && (
            <p className="field-help">
              Supported Store catalogue products only. No applicable update is reported as a successful
              no-change result.
            </p>
          )}
        </>
      )}
      {(kind === "winget.upgrade" || kind === "applications.upgrade") && (
        <>
          <label htmlFor="version">Exact target version</label>
          <input id="version" name="version" required placeholder="For example, 0.99.0" />
          <p className="field-help">
            Use the exact published version. “Latest” and “unknown” are not accepted.
          </p>
        </>
      )}
      {kind === "package.install" && (
        <>
          <label htmlFor="releaseId">Signed release</label>
          <select id="releaseId" name="releaseId" required>
            <option value="">Choose a trusted release</option>
            {releases
              .filter((release) => Date.parse(release.manifest.expiresAt) > Date.now())
              .map((release) => (
                <option key={release.id} value={release.id}>
                  {release.package_id} · {release.manifest.version} · #{release.sequence}
                </option>
              ))}
          </select>
          {!releases.length && (
            <p className="field-help">Register a signed release before creating this operation.</p>
          )}
        </>
      )}
      <div className="form-columns">
        <div>
          <label htmlFor="startsAt">Start (your local time)</label>
          <input
            id="startsAt"
            type="datetime-local"
            name="startsAt"
            required
            defaultValue={localTime(Date.now())}
          />
        </div>
        <div>
          <label htmlFor="endsAt">End (your local time)</label>
          <input
            id="endsAt"
            type="datetime-local"
            name="endsAt"
            required
            defaultValue={localTime(Date.now() + 3600_000)}
          />
        </div>
      </div>
      <div className="notice">
        <Lock size={17} />
        <p>
          {mutating
            ? "This request will wait for a separate approver. Managed updates accept source and package terms under organisation policy."
            : "This read-only operation can run during the selected window without installation approval."}
        </p>
      </div>
      {formError && (
        <p className="error" role="alert">
          {formError}
        </p>
      )}
      <button
        type="submit"
        className="primary"
        disabled={
          busy ||
          selected.length === 0 ||
          (kind === "windows.install" && (!chosenUpdates.length || chosenUpdates.length > 100))
        }
      >
        Create operation <ChevronRight size={14} />
      </button>
    </form>
  );
}
