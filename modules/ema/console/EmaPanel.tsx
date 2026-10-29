import { Monitor, RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Empty } from "../../../apps/console/src/components.js";
import {
  failed,
  pending,
  type Section,
  SectionNotice,
  snapshot,
} from "../../../apps/console/src/section-state.js";
import { date } from "../../../apps/console/src/view-model.js";

interface EmaInventory {
  configured: boolean;
  collectedAt?: string;
  endpoints: {
    id: string;
    hostname: string;
    groupName: string | null;
    agentConnected: boolean | null;
    ciraConnected: boolean | null;
    amtProvisioningState: string | number | null;
    amtControlMode: string | number | null;
  }[];
}
function connection(value: boolean | null) {
  return value === null ? "Unknown" : value ? "Connected" : "Disconnected";
}
function amtState(value: string | number | null) {
  return typeof value === "number" ? `EMA code ${value}` : (value ?? "Unknown");
}
export function EmaPanel({
  readInventory,
  isCurrent,
}: {
  readInventory: () => Promise<EmaInventory>;
  isCurrent: () => boolean;
}) {
  const [section, setSection] = useState<Section<EmaInventory>>({ status: "idle" });
  const request = useRef(0);
  useEffect(() => {
    return () => {
      request.current++;
    };
  }, []);
  const inventory = snapshot(section)?.data;
  const busy = section.status === "loading";
  const [search, setSearch] = useState("");
  const [connectionFilter, setConnectionFilter] = useState("all");
  const endpoints = inventory?.endpoints ?? [];
  const visible = endpoints.filter(
    (endpoint) =>
      `${endpoint.hostname} ${endpoint.groupName ?? ""}`.toLowerCase().includes(search.toLowerCase()) &&
      (connectionFilter === "all" ||
        (connectionFilter === "agent"
          ? endpoint.agentConnected === true
          : connectionFilter === "cira"
            ? endpoint.ciraConnected === true
            : endpoint.agentConnected === false)),
  );
  async function refresh() {
    const sequence = ++request.current;
    const current = () => isCurrent() && sequence === request.current;
    setSection(pending);
    try {
      const data = await readInventory();
      if (
        !data ||
        typeof data.configured !== "boolean" ||
        !Array.isArray(data.endpoints) ||
        !data.endpoints.every(
          (endpoint) =>
            endpoint &&
            typeof endpoint.id === "string" &&
            typeof endpoint.hostname === "string" &&
            (endpoint.groupName === null || typeof endpoint.groupName === "string") &&
            [endpoint.agentConnected, endpoint.ciraConnected].every(
              (value) => value === null || typeof value === "boolean",
            ) &&
            [endpoint.amtProvisioningState, endpoint.amtControlMode].every(
              (value) => value === null || typeof value === "number" || typeof value === "string",
            ),
        )
      )
        throw new Error("The control plane returned invalid EMA inventory.");
      if (current())
        setSection({ status: "loaded", snapshot: { data, updatedAt: new Date().toISOString() } });
    } catch (error) {
      if (current()) setSection((previous) => failed(previous, error));
    }
  }
  return (
    <section className="panel integration">
      <div className="panel-heading">
        <h2>
          <Monitor size={19} />
          Intel EMA
        </h2>
        <button type="button" className="small-button" disabled={busy} onClick={() => void refresh()}>
          <RefreshCw size={13} />
          {busy ? "Reading inventory…" : "Read EMA inventory"}
        </button>
      </div>
      <p>
        Existing EMA enrollments remain independent. AMT availability depends on hardware, provisioning and
        connectivity.
      </p>
      <SectionNotice name="Intel EMA" section={section} />
      {inventory?.configured ? (
        <>
          <p>Last read: {inventory.collectedAt ? date(inventory.collectedAt) : "Unknown"}</p>
          <p>
            {endpoints.length} registered ·{" "}
            {endpoints.filter((endpoint) => endpoint.agentConnected === true).length} software agents
            connected · {endpoints.filter((endpoint) => endpoint.ciraConnected === true).length} AMT tunnels
            connected
          </p>
          <div className="form-columns">
            <div>
              <label htmlFor="ema-search">Find EMA computer or group</label>
              <input id="ema-search" value={search} onChange={(event) => setSearch(event.target.value)} />
            </div>
            <div>
              <label htmlFor="ema-connection">Connection filter</label>
              <select
                id="ema-connection"
                value={connectionFilter}
                onChange={(event) => setConnectionFilter(event.target.value)}
              >
                <option value="all">All registered endpoints</option>
                <option value="agent">Software agent connected</option>
                <option value="cira">AMT tunnel connected</option>
                <option value="offline">Software agent disconnected</option>
              </select>
            </div>
          </div>
          {inventory.endpoints.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Computer</th>
                    <th>EMA group</th>
                    <th>Software agent</th>
                    <th>AMT tunnel</th>
                    <th>AMT provisioning</th>
                    <th>Control mode</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((endpoint) => (
                    <tr key={endpoint.id}>
                      <td>{endpoint.hostname}</td>
                      <td>{endpoint.groupName ?? "Unknown"}</td>
                      <td>{connection(endpoint.agentConnected)}</td>
                      <td>{connection(endpoint.ciraConnected)}</td>
                      <td>{amtState(endpoint.amtProvisioningState)}</td>
                      <td>{amtState(endpoint.amtControlMode)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!visible.length && <p>No computers match these filters.</p>}
            </div>
          ) : (
            <Empty
              icon={Monitor}
              title="No EMA endpoints returned"
              text="Check this account's access to your existing endpoint groups."
            />
          )}
        </>
      ) : inventory ? (
        <Empty
          icon={Monitor}
          title="Intel EMA is not configured"
          text="IT can connect the existing EMA server using a scoped account on the control plane."
        />
      ) : section.status === "idle" ? (
        <Empty
          icon={Monitor}
          title="Read the existing EMA inventory"
          text="Review software-agent and AMT connectivity separately before planning remote management."
        />
      ) : null}
    </section>
  );
}
