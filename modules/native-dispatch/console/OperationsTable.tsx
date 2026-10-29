import type { Device, Job, JobState } from "@one-control/protocol";
import { Check, ChevronRight, Download, Search } from "lucide-react";
import { useState } from "react";
import { Empty } from "../../../apps/console/src/components.js";
import { date, jobStates, labels, short } from "../../../apps/console/src/view-model.js";
import { StateBadge } from "./OperationDetails.js";

export function OperationsTable({
  jobs,
  devices,
  actor,
  operator,
  approver,
  busy,
  open,
  review,
  cancel,
  compact = false,
}: {
  jobs: Job[];
  devices: Device[];
  actor: string;
  operator: boolean;
  approver: boolean;
  busy: boolean;
  open: (job: Job) => void;
  review: (job: Job) => void;
  cancel: (job: Job) => void;
  compact?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [state, setState] = useState("all");
  const [provider, setProvider] = useState("all");
  const hostname = (id: string) => devices.find((device) => device.id === id)?.hostname ?? short(id);
  const filtered = jobs.filter(
    (job) =>
      (state === "all" || job.state === state) &&
      (provider === "all" || job.kind === provider) &&
      `${hostname(job.device_id)} ${job.id} ${job.batch_id} ${JSON.stringify(job.command)}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const shown = compact ? filtered.slice(0, 5) : filtered;
  return (
    <>
      {!compact && (
        <div className="table-toolbar">
          <div className="search">
            <Search size={15} />
            <input
              aria-label="Search operations"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Computer, operation or package"
            />
          </div>
          <select
            aria-label="Filter operation state"
            value={state}
            onChange={(event) => setState(event.target.value)}
          >
            <option value="all">All states</option>
            {Object.entries(jobStates).map(([id, value]) => (
              <option key={id} value={id}>
                {value.label}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter operation provider"
            value={provider}
            onChange={(event) => setProvider(event.target.value)}
          >
            <option value="all">All providers</option>
            {Object.entries(labels).map(([id, value]) => (
              <option key={id} value={id}>
                {value}
              </option>
            ))}
          </select>
          <span className="subtle">{shown.length} results</span>
        </div>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Operation</th>
              <th>Computer</th>
              <th>State</th>
              <th>Maintenance window</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((job) => (
              <tr key={job.id}>
                <td>
                  <button type="button" className="text-button" onClick={() => open(job)}>
                    {labels[job.kind]}
                    <small>
                      {short(job.id)} · {job.context}
                    </small>
                  </button>
                </td>
                <td>{hostname(job.device_id)}</td>
                <td>
                  <StateBadge state={job.state} />
                </td>
                <td>
                  {date(job.starts_at)}
                  <small>until {date(job.ends_at)}</small>
                </td>
                <td>
                  {job.state === "awaiting_approval" && approver && job.created_by !== actor ? (
                    <button
                      type="button"
                      className="small-button"
                      disabled={busy}
                      onClick={() => review(job)}
                    >
                      <Check size={13} />
                      Review batch
                    </button>
                  ) : (["queued", "awaiting_approval"] as JobState[]).includes(job.state) && operator ? (
                    <button type="button" className="text-button" disabled={busy} onClick={() => cancel(job)}>
                      Cancel pending batch
                    </button>
                  ) : (
                    <button type="button" className="text-button" onClick={() => open(job)}>
                      {job.state === "indeterminate" ? "Review outcome" : "View receipt"}
                      <ChevronRight size={13} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!shown.length && (
        <Empty
          icon={Download}
          title={jobs.length ? "No operations match these filters" : "No operations yet"}
          text={
            jobs.length
              ? "Change the state, provider or search to see other operations."
              : "Start with an inventory refresh or Windows Update scan. Installations require a separate approver."
          }
        />
      )}
    </>
  );
}
