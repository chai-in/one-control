import { record, text } from "../../../apps/console/src/view-model.js";

const pauseReasons: Record<number, string> = {
  0: "No reason reported",
  1: "High disk activity",
  2: "High CPU usage",
  3: "High notification rate",
  4: "Low battery",
  5: "Low memory",
  6: "Low disk space",
  7: "Recovery delayed",
  8: "User activity",
  9: "External request",
  10: "Upgrade in progress",
};

export function IndexingResult({ result }: { result: Record<string, unknown> }) {
  const after = record(result.after);
  const before = record(result.before);
  const catalog = record(after?.catalog);
  if (!after && !before) return null;
  return (
    <section aria-label="Windows Search result">
      <h3>Windows Search</h3>
      {after?.supported === false ? (
        <p>The Windows Search feature is not installed on this computer.</p>
      ) : (
        <dl className="facts">
          <div>
            <dt>Service</dt>
            <dd>{text(after?.service)}</dd>
          </div>
          <div>
            <dt>Startup</dt>
            <dd>{text(after?.startup)}</dd>
          </div>
          <div>
            <dt>Indexing activity</dt>
            <dd>{text(catalog?.status)}</dd>
          </div>
          {typeof catalog?.items === "number" && (
            <div>
              <dt>Indexed items</dt>
              <dd>{catalog.items.toLocaleString()}</dd>
            </div>
          )}
          {catalog?.status === "paused" && (
            <div>
              <dt>Indexer pause reason</dt>
              <dd>
                {typeof catalog.pausedReason === "number"
                  ? (pauseReasons[catalog.pausedReason] ?? `Reason ${catalog.pausedReason}`)
                  : "Not reported"}
              </dd>
            </div>
          )}
          <div>
            <dt>Location scope</dt>
            <dd>
              {after?.locationScope === "not-collected"
                ? "Not collected by this provider version"
                : text(after?.locationScope)}
            </dd>
          </div>
          {before && (
            <div>
              <dt>Before this operation</dt>
              <dd>
                {text(before.service)} · {text(before.startup)}
              </dd>
            </div>
          )}
        </dl>
      )}
      {Array.isArray(after?.locations) && (
        <>
          <h4>Configured crawl rules</h4>
          <p>
            These are configured rules. Access permissions and effective policy can further restrict indexed
            locations.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Location</th>
                  <th>Rule</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {after.locations
                  .map(record)
                  .filter((value) => value !== null)
                  .map((location) => (
                    <tr key={JSON.stringify([location.pattern, location.included, location.default])}>
                      <td className="break-text">{text(location.pattern)}</td>
                      <td>{location.included === true ? "Include" : "Exclude"}</td>
                      <td>{location.default === true ? "Default" : "Custom"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {after?.pauseMechanism === "service-stop-fallback" && (
        <p>
          Temporary stop preserves startup settings and catalog rules. It stops the Search service, so indexed
          queries are unavailable until the service starts again.
        </p>
      )}
    </section>
  );
}
