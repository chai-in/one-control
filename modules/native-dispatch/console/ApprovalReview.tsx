import { type BatchReview, commandContext } from "@one-control/protocol";
import { useState } from "react";
import { Dialog } from "../../../apps/console/src/Dialog.js";
import { date, labels } from "../../../apps/console/src/view-model.js";
import { CommandSummary } from "./OperationDetails.js";

export function ApprovalReview({
  review,
  busy,
  mutationDisabled = false,
  close,
  approve,
  error,
}: {
  review: BatchReview;
  busy: boolean;
  mutationDisabled?: boolean;
  close: () => void;
  approve: () => Promise<void>;
  error: string;
}) {
  const [confirmed, setConfirmed] = useState(false);
  return (
    <Dialog
      title="Review installation batch"
      close={close}
      closeLabel="Close approval review"
      wide
      busy={busy}
      error={error}
    >
      <p>
        <strong>{labels[review.command.kind]}</strong> · {review.ring} ring · {review.targets.length}{" "}
        computers
      </p>
      <p>
        Requested by {review.createdBy} on {date(review.createdAt)}
      </p>
      <h3>Exact operation</h3>
      <CommandSummary
        job={{
          command: review.command,
          kind: review.command.kind,
          context: commandContext(review.command),
        }}
      />
      {review.command.kind === "windows.install" && (
        <div className="update-list">
          {review.command.updates.map((update) => (
            <div key={`${update.id}:${update.revision}`}>
              <code>{update.id}</code>
              <span>Revision {update.revision}</span>
            </div>
          ))}
        </div>
      )}
      {review.release && (
        <>
          <h3>Signed release</h3>
          <dl className="facts two-columns">
            <div>
              <dt>Package / version</dt>
              <dd>
                {review.release.packageId} · {review.release.version}
              </dd>
            </div>
            <div>
              <dt>Sequence</dt>
              <dd>{review.release.sequence}</dd>
            </div>
            <div>
              <dt>Metadata expiry</dt>
              <dd>{date(review.release.expiresAt)}</dd>
            </div>
            <div>
              <dt>Artifact size</dt>
              <dd>{review.release.size.toLocaleString("en-IN")} bytes</dd>
            </div>
            <div className="span-columns">
              <dt>Publisher certificate</dt>
              <dd>
                <code>{review.release.publisherThumbprint}</code>
              </dd>
            </div>
            <div className="span-columns">
              <dt>Artifact SHA-256</dt>
              <dd>
                <code>{review.release.sha256}</code>
              </dd>
            </div>
            <div className="span-columns">
              <dt>Artifact URL</dt>
              <dd className="break-text">{review.release.artifactUrl}</dd>
            </div>
          </dl>
        </>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Computer / device ID</th>
              <th>Maintenance window</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {review.targets.map((target) => (
              <tr key={target.deviceId}>
                <td>
                  {target.hostname}
                  <small>{target.deviceId}</small>
                </td>
                <td>
                  {date(target.startsAt)}
                  <small>until {date(target.endsAt)}</small>
                </td>
                <td>{target.state.replaceAll("_", " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <label className="checkbox">
        <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
        I reviewed the exact operation and every target above.
      </label>
      <p className="subtle">
        This authorises the entire batch. Managed updates accept source and package terms under organisation
        policy. The server checks that the contents still match this review.
      </p>
      <button
        type="button"
        className="primary"
        disabled={busy || mutationDisabled || !confirmed}
        onClick={() => void approve()}
      >
        Approve reviewed batch
      </button>
    </Dialog>
  );
}
