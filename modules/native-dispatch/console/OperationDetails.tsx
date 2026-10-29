import type { Device, Job } from "@one-control/protocol";
import { CheckCircle2, Clock3, FileCheck2, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Dialog } from "../../../apps/console/src/Dialog.js";
import {
  availableUpdates,
  date,
  jobStates,
  labels,
  type OperationDraft,
  record,
  text,
} from "../../../apps/console/src/view-model.js";
import { IndexingResult } from "../../indexing/console/IndexingResult.js";

export function StateBadge({ state }: { state: Job["state"] }) {
  const status = jobStates[state];
  return <span className={`status ${status.tone}`}>{status.label}</span>;
}

export function CommandSummary({ job }: { job: Pick<Job, "kind" | "command" | "context"> }) {
  const command = job.command;
  return (
    <div className="command-summary">
      <div>
        <span className="eyebrow">OPERATION</span>
        <strong>{labels[job.kind]}</strong>
      </div>
      <div>
        <span className="eyebrow">EXECUTION</span>
        <strong>{job.context === "system" ? "SYSTEM service" : "Signed-in user"}</strong>
      </div>
      {(command.kind === "winget.upgrade" || command.kind === "store.upgrade") && (
        <>
          <div>
            <span className="eyebrow">PACKAGE</span>
            <strong>{command.packageId}</strong>
          </div>
          <div>
            <span className="eyebrow">TARGET VERSION</span>
            <strong>
              {command.kind === "winget.upgrade" ? command.version : "Applicable Store catalogue update"}
            </strong>
          </div>
        </>
      )}
      {command.kind === "windows.install" && (
        <div>
          <span className="eyebrow">APPROVED UPDATES</span>
          <strong>{command.updates.length} exact IDs and revisions</strong>
        </div>
      )}
      {command.kind === "indexing.enable" && (
        <div>
          <span className="eyebrow">APPROVED STARTUP</span>
          <strong>{command.startup}</strong>
        </div>
      )}
    </div>
  );
}

function Result({
  job,
  device,
  createOperation,
}: {
  job: Job;
  device: Device | undefined;
  createOperation?: (draft: OperationDraft) => void;
}) {
  const result = job.result;
  if (!result)
    return (
      <div className="notice">
        <Clock3 size={17} />
        <div>
          <strong>No result yet</strong>
          <p>{jobStates[job.state].description}</p>
        </div>
      </div>
    );
  const updates = availableUpdates(result);
  const entries = [
    ...new Map(
      (Array.isArray(result.updates) ? result.updates.map(record).filter((value) => value !== null) : []).map(
        (value) => [JSON.stringify([value.id, value.resultCode, value.hresult]), value],
      ),
    ).values(),
  ];
  return (
    <div className="result-content">
      {job.kind.startsWith("indexing.") && <IndexingResult result={result} />}
      {result.reconciledBy !== undefined && (
        <div className="notice">
          <FileCheck2 size={18} />
          <div>
            <strong>Verified by {text(result.reconciledBy)}</strong>
            <p>{text(result.evidence)}</p>
          </div>
        </div>
      )}
      {result.outcome === "no_applicable_update" && (
        <div className="notice success">
          <CheckCircle2 size={18} />
          <div>
            <strong>Already up to date for this request</strong>
            <p>The provider found no applicable update. No application change was reported.</p>
          </div>
        </div>
      )}
      {result.rollbackVerified === true && (
        <div className="notice success">
          <FileCheck2 size={18} />
          <div>
            <strong>Previous agent restored</strong>
            <p>The recovery service verified an authenticated heartbeat from the previous version.</p>
          </div>
        </div>
      )}
      {result.rebootRequired === true && (
        <div className="notice warning">
          <Clock3 size={18} />
          <div>
            <strong>A restart is required</strong>
            <p>Arrange the restart with the computer’s user. This console does not force a reboot.</p>
          </div>
        </div>
      )}
      {typeof result.reason === "string" && (
        <dl className="facts">
          <div>
            <dt>Reported outcome</dt>
            <dd>{result.reason.replaceAll("_", " ")}</dd>
          </div>
        </dl>
      )}
      {typeof result.exitCode === "number" && (
        <dl className="facts">
          <div>
            <dt>Provider exit code</dt>
            <dd>{result.exitCode}</dd>
          </div>
        </dl>
      )}
      {job.kind === "windows.scan" && job.state === "succeeded" && (
        <>
          <div className="section-heading">
            <h3>
              Available Windows updates <span className="count-pill">{updates.length}</span>
            </h3>
            {!!updates.length && device && !device.revoked_at && createOperation && (
              <button
                className="small-button"
                type="button"
                onClick={() => createOperation({ kind: "windows.install", deviceIds: [device.id] })}
              >
                Choose updates to install
              </button>
            )}
          </div>
          {updates.length ? (
            <div className="update-list">
              {updates.map((update) => (
                <div key={`${update.id}:${update.revision}`}>
                  <FileCheck2 size={17} />
                  <div>
                    <strong>{update.title}</strong>
                    <small>Revision {update.revision}</small>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="empty-copy">
              This scan reported no applicable software updates within the provider’s supported scope.
            </p>
          )}
        </>
      )}
      {job.kind === "windows.install" && entries.length > 0 && (
        <div className="update-list">
          {entries.map((entry) => (
            <div key={JSON.stringify([entry.id, entry.resultCode, entry.hresult])}>
              <FileCheck2 size={17} />
              <div>
                <strong>{text(entry.id)}</strong>
                <small>
                  Result {String(entry.resultCode ?? "not reported")} · HRESULT{" "}
                  {String(entry.hresult ?? "not reported")}
                </small>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function OperationDetails({
  job,
  device,
  operator,
  busy,
  close,
  reconcile,
  createOperation,
  error,
}: {
  job: Job;
  device: Device | undefined;
  operator: boolean;
  busy: boolean;
  close: () => void;
  reconcile: (state: "succeeded" | "failed", evidence: string) => Promise<void>;
  createOperation: (draft: OperationDraft) => void;
  error: string;
}) {
  const [showReconcile, setShowReconcile] = useState(false);
  const [outcome, setOutcome] = useState<"succeeded" | "failed">("failed");
  const [evidence, setEvidence] = useState("");
  const [verified, setVerified] = useState(false);
  return (
    <Dialog
      title={labels[job.kind] ?? "Operation details"}
      close={close}
      closeLabel="Close details"
      wide
      busy={busy}
      error={error}
    >
      <div className="detail-meta">
        <span>{device?.hostname ?? job.device_id}</span>
        <StateBadge state={job.state} />
        <code>{job.id.slice(0, 8)}</code>
      </div>
      <CommandSummary job={job} />
      <dl className="facts two-columns">
        <div>
          <dt>Requested by</dt>
          <dd>{job.created_by}</dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>{date(job.created_at)}</dd>
        </div>
        <div>
          <dt>Maintenance window</dt>
          <dd>
            {date(job.starts_at)} – {date(job.ends_at)}
          </dd>
        </div>
        <div>
          <dt>Completed</dt>
          <dd>{date(job.finished_at ?? null)}</dd>
        </div>
        <div>
          <dt>Dispatch attempts</dt>
          <dd>{job.attempt}</dd>
        </div>
        <div>
          <dt>Batch</dt>
          <dd className="break-text">{job.batch_id}</dd>
        </div>
      </dl>
      <h3 className="section-title">Result</h3>
      <Result job={job} device={device} {...(operator ? { createOperation } : {})} />
      {job.state === "indeterminate" && (
        <div className="reconciliation">
          <div className="notice warning">
            <ShieldAlert size={19} />
            <div>
              <strong>This computer is waiting for IT verification</strong>
              <p>
                {jobStates.indeterminate.description} Check its installed state and confirm the previous
                installer has ended.
              </p>
            </div>
          </div>
          {operator && !showReconcile && (
            <button className="secondary" type="button" onClick={() => setShowReconcile(true)}>
              Record a verified outcome
            </button>
          )}
          {operator && showReconcile && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                if (verified && evidence.trim().length >= 20) void reconcile(outcome, evidence.trim());
              }}
            >
              <label htmlFor="reconcile-outcome">Verified outcome</label>
              <select
                id="reconcile-outcome"
                value={outcome}
                onChange={(event) => setOutcome(event.target.value as "succeeded" | "failed")}
              >
                <option value="failed">Failed or did not complete as requested</option>
                <option value="succeeded">Succeeded — independently verified</option>
              </select>
              <label htmlFor="reconcile-evidence">What did you verify on the computer?</label>
              <textarea
                id="reconcile-evidence"
                value={evidence}
                onChange={(event) => setEvidence(event.target.value)}
                minLength={20}
                maxLength={2000}
                required
                placeholder="Record the installed version, installer state, health evidence, and when you checked."
              />
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={verified}
                  onChange={(event) => setVerified(event.target.checked)}
                  required
                />
                I checked the actual computer and confirmed the previous installer has ended.
              </label>
              <p className="subtle">
                This records an audited IT decision and releases quarantine. It does not rerun the operation.
              </p>
              <button
                className="primary"
                type="submit"
                disabled={busy || !verified || evidence.trim().length < 20}
              >
                Save verified outcome
              </button>
            </form>
          )}
        </div>
      )}
      <details className="technical-record">
        <summary>Technical record</summary>
        <pre>{JSON.stringify(job, null, 2)}</pre>
      </details>
    </Dialog>
  );
}
