import { RefreshCw, Shield } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Empty } from "../../../apps/console/src/components.js";
import {
  failed,
  pending,
  type Section,
  SectionNotice,
  snapshot,
} from "../../../apps/console/src/section-state.js";

type Capabilities = {
  configured: boolean;
  capabilities: { capability: string; status: string }[];
};

export function FalconPanel({
  readCapabilities,
  isCurrent,
}: {
  readCapabilities: () => Promise<Capabilities>;
  isCurrent: () => boolean;
}) {
  const [section, setSection] = useState<Section<Capabilities>>({ status: "idle" });
  const request = useRef(0);
  useEffect(() => {
    return () => {
      request.current++;
    };
  }, []);
  const falcon = snapshot(section)?.data;
  async function refresh() {
    const sequence = ++request.current;
    const current = () => isCurrent() && sequence === request.current;
    setSection(pending);
    try {
      const data = await readCapabilities();
      if (
        !data ||
        typeof data.configured !== "boolean" ||
        !Array.isArray(data.capabilities) ||
        !data.capabilities.every(
          (capability) =>
            capability && typeof capability.capability === "string" && typeof capability.status === "string",
        )
      )
        throw new Error("The control plane returned invalid Falcon capabilities.");
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
          <Shield size={19} />
          CrowdStrike Falcon
        </h2>
        <button
          type="button"
          className="small-button"
          disabled={section.status === "loading"}
          onClick={() => void refresh()}
        >
          <RefreshCw size={13} />
          Check read capabilities
        </button>
      </div>
      <p>Falcon enriches fleet visibility. API credentials stay on the control plane.</p>
      <SectionNotice name="Falcon" section={section} />
      {falcon ? (
        falcon.configured ? (
          <div className="capabilities">
            {falcon.capabilities.map((capability) => (
              <div key={capability.capability}>
                {capability.capability}
                <span className={`status ${capability.status === "available" ? "good" : "warning"}`}>
                  {capability.status}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <Empty
            icon={Shield}
            title="Falcon is not configured"
            text="IT can configure a scoped Falcon API client on the control plane."
          />
        )
      ) : section.status === "idle" ? (
        <Empty
          icon={Shield}
          title="Verify access before using a capability"
          text="Authentication alone does not establish access to every API. This check performs read-only requests."
        />
      ) : null}
    </section>
  );
}
