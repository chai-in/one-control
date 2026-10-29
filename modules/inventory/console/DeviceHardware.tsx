import { AlertTriangle, HardDrive } from "lucide-react";
import { bytes, disks, memoryCapacity, uptime } from "../../../apps/console/src/device-health.js";
import { record, text } from "../../../apps/console/src/view-model.js";
import "./device-hardware.css";

export function DeviceHardware({ inventory }: { inventory: Record<string, unknown> | null }) {
  const hardware = record(inventory?.hardware);
  const memory = memoryCapacity(inventory);
  const volumes = disks(inventory);
  return (
    <section className="hardware-section" aria-labelledby="hardware-title">
      <h3 id="hardware-title" className="section-title">
        Hardware & capacity
      </h3>
      {!hardware ? (
        <p className="empty-copy">Hardware details have not been reported by this agent.</p>
      ) : (
        <>
          <dl className="facts two-columns">
            <div>
              <dt>Computer model</dt>
              <dd>
                {[text(hardware.manufacturer, ""), text(hardware.model, "")].filter(Boolean).join(" · ") ||
                  "Not reported"}
              </dd>
            </div>
            <div>
              <dt>Processor</dt>
              <dd>{text(hardware.processor)}</dd>
            </div>
            <div>
              <dt>Logical processors</dt>
              <dd>
                {typeof hardware.logicalProcessors === "number" &&
                Number.isSafeInteger(hardware.logicalProcessors) &&
                hardware.logicalProcessors > 0
                  ? hardware.logicalProcessors
                  : "Not reported"}
              </dd>
            </div>
            <div>
              <dt>Memory</dt>
              <dd>
                {memory ? `${bytes(memory.total)} total` : "Not reported"}
                {memory?.available !== null && memory?.available !== undefined && (
                  <small>{bytes(memory.available)} available at collection</small>
                )}
              </dd>
            </div>
            <div>
              <dt>Uptime at collection</dt>
              <dd>{uptime(hardware.uptimeSeconds)}</dd>
            </div>
          </dl>
          <div className="disk-list">
            {volumes.map((disk) => (
              <div className="disk-card" key={disk.name}>
                <div className="disk-heading">
                  <HardDrive size={18} aria-hidden="true" />
                  <strong>{disk.name}</strong>
                  {disk.system && <span className="ring">Windows volume</span>}
                  <span className="disk-format">{disk.fileSystem}</span>
                </div>
                {disk.capacity ? (
                  <>
                    <div className="disk-values">
                      <strong>{bytes(disk.capacity.free)} free</strong>
                      <span>of {bytes(disk.capacity.total)}</span>
                    </div>
                    <meter
                      aria-label={`Free disk space on ${disk.name}`}
                      min={0}
                      max={disk.capacity.total}
                      value={disk.capacity.free}
                      low={disk.capacity.total * 0.1}
                      optimum={disk.capacity.total}
                    />
                    {disk.capacity.low && (
                      <p className="disk-warning">
                        <AlertTriangle size={14} aria-hidden="true" />
                        Less than 10% free space
                      </p>
                    )}
                  </>
                ) : (
                  <p className="empty-copy">Capacity unavailable at collection.</p>
                )}
              </div>
            ))}
          </div>
          {!volumes.length && <p className="empty-copy">No local fixed-volume capacity has been reported.</p>}
          <p className="subtle">
            Capacity and uptime reflect the last inventory. Network shares and removable drives are outside
            this view.
          </p>
        </>
      )}
    </section>
  );
}
