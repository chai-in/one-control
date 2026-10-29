import type { Device } from "@one-control/protocol";
import { Monitor, Search } from "lucide-react";
import { useState } from "react";
import { Empty } from "./components.js";
import { attention } from "./device-health.js";
import { connection, date, relativeTime, short, text } from "./view-model.js";

export function FleetTable({ devices, open }: { devices: Device[]; open: (device: Device) => void }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("managed");
  const [ring, setRing] = useState("all");
  const [health, setHealth] = useState("all");
  const visible = devices.filter((device) => {
    const state = connection(device).label.toLowerCase();
    const signals = attention(device.inventory);
    return (
      (status === "all" || (status === "managed" ? !device.revoked_at : state === status)) &&
      (ring === "all" || device.ring === ring) &&
      (health === "all" ||
        (health === "attention" ? signals.length > 0 : signals.some((signal) => signal.code === health))) &&
      `${device.hostname} ${device.id} ${device.ring}`.toLowerCase().includes(query.toLowerCase())
    );
  });
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>
          Device inventory <span className="count-pill">{visible.length}</span>
        </h2>
        <span className="subtle">Last 1,000 enrollment records</span>
      </div>
      <div className="table-toolbar">
        <div className="search">
          <Search size={15} />
          <input
            aria-label="Search devices"
            placeholder="Find a computer"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
        <select
          aria-label="Filter devices by connection"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
        >
          <option value="managed">Managed computers</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="revoked">Revoked</option>
          <option value="all">All records</option>
        </select>
        <select
          aria-label="Filter devices by ring"
          value={ring}
          onChange={(event) => setRing(event.target.value)}
        >
          <option value="all">All rings</option>
          {["canary", "pilot", "broad"].map((value) => (
            <option key={value}>{value}</option>
          ))}
        </select>
        <select
          aria-label="Filter devices by attention"
          value={health}
          onChange={(event) => setHealth(event.target.value)}
        >
          <option value="all">All conditions</option>
          <option value="attention">Needs attention</option>
          <option value="low_space">Low disk space</option>
          <option value="recovery">Recovery stopped</option>
          <option value="restart">Restart needed</option>
          <option value="partial">Partial inventory</option>
        </select>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Computer</th>
              <th>Connection</th>
              <th>Agent / recovery</th>
              <th>Ring</th>
              <th>Last seen</th>
              <th>Reported attention</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((device) => {
              const state = connection(device);
              const signals = attention(device.inventory);
              return (
                <tr key={device.id}>
                  <td>
                    <button className="text-button cell-title" type="button" onClick={() => open(device)}>
                      <Monitor size={18} />
                      <span>
                        <strong>{device.hostname}</strong>
                        <small>{short(device.id)}</small>
                      </span>
                    </button>
                  </td>
                  <td>
                    <span className={`status ${state.tone}`}>{state.label}</span>
                  </td>
                  <td>
                    {text(device.inventory?.agentVersion, "Not reported")}
                    <small>
                      {device.inventory?.agentRecoveryReady === true
                        ? "Recovery ready"
                        : device.inventory?.agentRecoveryReady === false
                          ? "Recovery unavailable"
                          : "Recovery not reported"}
                    </small>
                  </td>
                  <td>
                    <span className="ring">{device.ring}</span>
                  </td>
                  <td title={date(device.last_seen_at)}>{relativeTime(device.last_seen_at)}</td>
                  <td>
                    {signals.length ? (
                      <div className="attention-list">
                        {signals.map((signal) => (
                          <span key={signal.code} className={`status ${signal.tone}`}>
                            {signal.label}
                          </span>
                        ))}
                      </div>
                    ) : (
                      "None reported"
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {!visible.length && (
        <Empty
          icon={Monitor}
          title={devices.length ? "No computers match these filters" : "Your fleet starts here"}
          text={
            devices.length
              ? "Change the connection or ring filter, or search for another computer."
              : "Enroll an approved POC computer to start collecting inventory and planning updates."
          }
        />
      )}
    </section>
  );
}
