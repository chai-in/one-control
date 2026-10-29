import type { Config } from "../../../apps/control-plane/src/config.js";

export interface Capability {
  capability: string;
  status: "available" | "denied" | "unlicensed" | "error";
  httpStatus: number | null;
}
// Deliberately read-only. A successful OAuth token does not imply every API scope.
export async function probeFalcon(
  config: Config,
  signal: AbortSignal = AbortSignal.timeout(30_000),
): Promise<{ configured: boolean; capabilities: Capability[] }> {
  if (!config.FALCON_CLIENT_ID || !config.FALCON_CLIENT_SECRET || !config.FALCON_CLOUD)
    return { configured: false, capabilities: [] };
  const auth = await fetch(`${config.FALCON_CLOUD}/oauth2/token`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
    body: new URLSearchParams({
      client_id: config.FALCON_CLIENT_ID,
      client_secret: config.FALCON_CLIENT_SECRET,
    }),
  });
  if (!auth.ok) throw new Error("Falcon authentication unavailable");
  const token = (await auth.json()) as { access_token: string };
  const capabilities: Capability[] = [];
  for (const [capability, path] of [
    ["hosts", "/devices/queries/devices/v1?limit=1"],
    ["rtr", "/real-time-response/queries/sessions/v1?limit=1"],
    ["rtrAdmin", "/real-time-response/queries/scripts/v1?limit=1"],
    ["assets", "/discover/queries/hosts/v1?limit=1"],
    ["alerts", "/alerts/queries/alerts/v2?limit=1"],
    ["sensorUpdatePolicies", "/policy/queries/sensor-update/v1?limit=1"],
  ] as const) {
    signal.throwIfAborted();
    try {
      const response = await fetch(`${config.FALCON_CLOUD}${path}`, {
        redirect: "error",
        headers: { Authorization: `Bearer ${token.access_token}` },
        signal: AbortSignal.any([signal, AbortSignal.timeout(10_000)]),
      });
      await response.body?.cancel();
      capabilities.push({
        capability,
        httpStatus: response.status,
        status: response.ok
          ? "available"
          : response.status === 403
            ? "denied"
            : response.status === 402
              ? "unlicensed"
              : "error",
      });
    } catch {
      capabilities.push({ capability, status: "error", httpStatus: null });
    }
  }
  return { configured: true, capabilities };
}
