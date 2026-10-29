// SPDX-License-Identifier: GPL-3.0-only
// REST resource mappings adapted from TIBCON Sentry; see docs/sentry-integration.json.
import { z } from "zod";
import type { Config } from "../../../apps/control-plane/src/config.js";
import { ApiError } from "../../../apps/control-plane/src/security.js";

export const falconResource = z.enum([
  "hosts",
  "assets",
  "applications",
  "groups",
  "vulnerabilities",
  "alerts",
  "incidents",
  "device-control",
  "prevention",
  "sensor-update",
]);
type Resource = z.infer<typeof falconResource>;
type Envelope<T> = {
  resources: T[];
  errors?: { code: number; message: string }[];
  meta?: { pagination?: { total?: number; after?: string } };
};
export const falconPageQuery = z.strictObject({
  scopeId: z.uuid(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100000).default(0),
  after: z.string().max(2048).optional(),
  filter: z.string().max(1024).optional(),
});
const mapping: Record<
  Exclude<Resource, "vulnerabilities">,
  { query: string; entities?: string; body?: string }
> = {
  hosts: { query: "/devices/queries/devices/v1", entities: "/devices/entities/devices/v2", body: "ids" },
  assets: { query: "/discover/queries/hosts/v1", entities: "/discover/entities/hosts/v1" },
  applications: {
    query: "/discover/queries/applications/v1",
    entities: "/discover/entities/applications/v1",
  },
  groups: { query: "/devices/queries/host-groups/v1", entities: "/devices/entities/host-groups/v1" },
  alerts: {
    query: "/alerts/queries/alerts/v2",
    entities: "/alerts/entities/alerts/v2",
    body: "composite_ids",
  },
  incidents: {
    query: "/incidents/queries/incidents/v1",
    entities: "/incidents/entities/incidents/GET/v1",
    body: "ids",
  },
  "device-control": { query: "/policy/combined/device-control/v1" },
  prevention: { query: "/policy/combined/prevention/v1" },
  "sensor-update": { query: "/policy/combined/sensor-update/v1" },
};

export class FalconInventory {
  private token?: string;
  constructor(
    private readonly config: Config,
    private readonly signal: AbortSignal,
  ) {}
  get configured() {
    return Boolean(
      this.config.FALCON_CLOUD && this.config.FALCON_CLIENT_ID && this.config.FALCON_CLIENT_SECRET,
    );
  }
  private async call<T>(path: string, query?: URLSearchParams, body?: object): Promise<Envelope<T>> {
    if (!this.configured) throw new ApiError(503, "falcon_unconfigured");
    if (!this.token) {
      const response = await fetch(`${this.config.FALCON_CLOUD}/oauth2/token`, {
        method: "POST",
        redirect: "error",
        signal: this.signal,
        body: new URLSearchParams({
          client_id: this.config.FALCON_CLIENT_ID as string,
          client_secret: this.config.FALCON_CLIENT_SECRET as string,
        }),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw new ApiError(503, "falcon_unavailable");
      }
      const authentication = z.object({ access_token: z.string().min(1) }).parse(await response.json());
      this.token = authentication.access_token;
    }
    const response = await fetch(`${this.config.FALCON_CLOUD}${path}${query?.size ? `?${query}` : ""}`, {
      method: body ? "POST" : "GET",
      redirect: "error",
      signal: this.signal,
      headers: {
        Authorization: `Bearer ${this.token}`,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new ApiError(
        response.status === 403 ? 403 : 503,
        response.status === 403
          ? "falcon_scope_denied"
          : response.status === 402
            ? "falcon_unlicensed"
            : response.status === 429
              ? "falcon_rate_limited"
              : "falcon_unavailable",
      );
    }
    const data = (await response.json()) as Envelope<T>;
    if (!Array.isArray(data.resources) || data.errors?.length)
      throw new ApiError(503, "falcon_incomplete_response");
    return data;
  }
  async page(resource: Resource, input: z.output<typeof falconPageQuery>) {
    const query = new URLSearchParams({ limit: String(input.limit) });
    if (input.filter) query.set("filter", input.filter);
    let page: Envelope<unknown>;
    let records: unknown[];
    if (resource === "vulnerabilities") {
      query.set("filter", input.filter || "status:'open'");
      query.set("facet", "cve");
      if (input.after) query.set("after", input.after);
      page = await this.call("/spotlight/combined/vulnerabilities/v1", query);
      records = page.resources;
    } else {
      const spec = mapping[resource];
      query.set("offset", String(input.offset));
      page = await this.call(spec.query, query);
      if (spec.entities && page.resources.length) {
        const ids = z.array(z.string()).parse(page.resources);
        const params = new URLSearchParams();
        for (const id of ids) params.append("ids", id);
        records = (
          await this.call(
            spec.entities,
            spec.body ? undefined : params,
            spec.body ? { [spec.body]: ids } : undefined,
          )
        ).resources;
      } else records = spec.entities ? [] : page.resources;
    }
    const total = page.meta?.pagination?.total ?? null;
    return {
      configured: true,
      resource,
      records,
      total,
      collectedAt: new Date().toISOString(),
      next:
        resource === "vulnerabilities"
          ? page.meta?.pagination?.after
            ? { after: page.meta.pagination.after }
            : null
          : (total === null
                ? page.resources.length === input.limit
                : input.offset + page.resources.length < total) && page.resources.length
            ? { offset: input.offset + page.resources.length }
            : null,
    };
  }
  async host(id: string) {
    return (
      (await this.call<Record<string, unknown>>("/devices/entities/devices/v2", undefined, { ids: [id] }))
        .resources[0] ?? null
    );
  }
  async assessment(id: string) {
    return (
      await this.call<Record<string, unknown>>(
        "/zero-trust-assessment/entities/assessments/v1",
        new URLSearchParams({ ids: id }),
      )
    ).resources;
  }
}
