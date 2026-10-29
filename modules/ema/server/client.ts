import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";

const tokenSchema = z.object({
  access_token: z.string().min(1).max(16_384),
  expires_in: z.number().int().positive().max(86_400).default(3600),
});
// EMA 1.15 serializes these enums as integers; the published examples use names.
// Preserve both representations without guessing undocumented numeric meanings.
const amtStateSchema = z.union([z.string().max(128), z.number().int().nonnegative()]);
const endpointSchema = z.object({
  EndpointId: z.string().min(1).max(128),
  ComputerName: z.string().max(256),
  EndpointGroupId: z.string().max(128).nullable().optional(),
  EndpointGroupName: z.string().max(256).nullable().optional(),
  IsConnected: z.boolean().nullable().optional(),
  IsCiraConnected: z.boolean().nullable().optional(),
  IsAmtVersionValid: z.boolean().nullable().optional(),
  AmtControlMode: amtStateSchema.nullable().optional(),
  AmtProvisioningState: amtStateSchema.nullable().optional(),
  PowerState: z.number().int().nullable().optional(),
});
const endpointsSchema = z.array(endpointSchema).max(10_000);

export interface EmaEndpoint {
  id: string;
  hostname: string;
  groupId: string | null;
  groupName: string | null;
  agentConnected: boolean | null;
  ciraConnected: boolean | null;
  amtVersionValid: boolean | null;
  amtControlMode: string | number | null;
  amtProvisioningState: string | number | null;
  powerState: number | null;
}

export class EmaUnavailable extends Error {
  constructor(public readonly httpStatus: number | null = null) {
    // Upstream bodies, URLs and credentials must never reach an API error or log.
    super("Intel EMA unavailable");
  }
}

async function json(response: Response, limit: number): Promise<unknown> {
  if (!response.headers.get("content-type")?.toLowerCase().startsWith("application/json"))
    throw new EmaUnavailable(response.status);
  if (!response.body) throw new EmaUnavailable(response.status);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      length += next.value.byteLength;
      if (length > limit) throw new EmaUnavailable(response.status);
      chunks.push(next.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

/** Server-side, read-only adapter. No browser/agent receives EMA credentials or bearer tokens.
 * Contract retained from legacy OneControl and verified against Intel's EMA REST reference.
 * Provisioning, software execution, power actions and KVM require their own future policy.
 */
export class EmaClient {
  readonly configured: boolean;
  private token: { value: string; expiresAt: number } | undefined;
  private minting: Promise<string> | undefined;

  constructor(
    private readonly config: Pick<Config, "EMA_BASE_URL" | "EMA_USERNAME" | "EMA_PASSWORD">,
    private readonly request: typeof fetch = fetch,
  ) {
    this.configured = Boolean(config.EMA_BASE_URL && config.EMA_USERNAME && config.EMA_PASSWORD);
  }

  private async accessToken(): Promise<string> {
    if (this.token && this.token.expiresAt > Date.now()) return this.token.value;
    if (this.minting) return this.minting;
    const pending = this.mint();
    this.minting = pending;
    try {
      return await pending;
    } finally {
      if (this.minting === pending) this.minting = undefined;
    }
  }

  private async mint(): Promise<string> {
    const { EMA_BASE_URL, EMA_USERNAME, EMA_PASSWORD } = this.config;
    if (!EMA_BASE_URL || !EMA_USERNAME || !EMA_PASSWORD) throw new EmaUnavailable();
    const response = await this.request(new URL("/api/token", EMA_BASE_URL), {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      headers: { Accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "password",
        username: EMA_USERNAME,
        password: EMA_PASSWORD,
      }),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new EmaUnavailable(response.status);
    }
    const token = tokenSchema.parse(await json(response, 65_536));
    const lifetimeMs = token.expires_in * 1000;
    this.token = {
      value: token.access_token,
      expiresAt: Date.now() + lifetimeMs - Math.min(60_000, lifetimeMs / 10),
    };
    return token.access_token;
  }

  async endpoints(hostname?: string): Promise<EmaEndpoint[]> {
    try {
      const url = new URL("/api/latest/endpoints", this.config.EMA_BASE_URL);
      if (hostname) url.searchParams.set("computerName", hostname);
      for (let attempt = 0; attempt < 2; attempt++) {
        const token = await this.accessToken();
        const response = await this.request(url, {
          method: "GET",
          redirect: "error",
          signal: AbortSignal.timeout(15_000),
          headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
        });
        if (!response.ok) {
          await response.body?.cancel();
          if (response.status === 401 && attempt === 0) {
            if (this.token?.value === token) this.token = undefined;
            continue; // Only this read can be repeated after refreshing authentication.
          }
          throw new EmaUnavailable(response.status);
        }
        const rows = endpointsSchema.parse(await json(response, 4_194_304));
        if (new Set(rows.map((row) => row.EndpointId)).size !== rows.length) throw new EmaUnavailable();
        return rows.map((row) => ({
          id: row.EndpointId,
          hostname: row.ComputerName,
          groupId: row.EndpointGroupId ?? null,
          groupName: row.EndpointGroupName ?? null,
          agentConnected: row.IsConnected ?? null,
          ciraConnected: row.IsCiraConnected ?? null,
          amtVersionValid: row.IsAmtVersionValid ?? null,
          amtControlMode: row.AmtControlMode ?? null,
          amtProvisioningState: row.AmtProvisioningState ?? null,
          powerState: row.PowerState ?? null,
        }));
      }
      throw new EmaUnavailable();
    } catch (error) {
      if (error instanceof EmaUnavailable) throw error;
      throw new EmaUnavailable();
    }
  }
}
