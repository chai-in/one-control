import { afterEach, describe, expect, test, vi } from "vitest";
import { EmaClient, EmaUnavailable } from "../../../modules/ema/server/client.js";
import { parseConfig } from "../src/config.js";

const settings = {
  EMA_BASE_URL: "https://ema.example.test/",
  EMA_USERNAME: "one-control-reader",
  EMA_PASSWORD: "private-password",
};
const row = {
  EndpointId: "a".repeat(64),
  ComputerName: "TESTING",
  IsConnected: true,
  IsCiraConnected: false,
};
function auth() {
  return Response.json({ access_token: "private-bearer", expires_in: 3600 });
}
afterEach(() => vi.unstubAllGlobals());

describe("independent Intel EMA adapter", () => {
  test("configuration is optional, complete and restricted to an HTTPS origin", () => {
    expect(new EmaClient(parseConfig({})).configured).toBe(false);
    expect(parseConfig(settings).EMA_BASE_URL).toBe(settings.EMA_BASE_URL);
    expect(() => parseConfig({ EMA_BASE_URL: settings.EMA_BASE_URL })).toThrow();
    for (const base of [
      "http://ema.example.test",
      "https://u:p@ema.example.test",
      "https://ema.example.test/path",
      "https://ema.example.test/?secret=1",
    ])
      expect(() => parseConfig({ ...settings, EMA_BASE_URL: base })).toThrow();
  });

  test("reuses one token across concurrent reads and separates agent from AMT connectivity", async () => {
    const request = vi.fn<typeof fetch>(async (url) =>
      new URL(String(url)).pathname === "/api/token" ? auth() : Response.json([row]),
    );
    const ema = new EmaClient(settings, request);
    const results = await Promise.all([ema.endpoints("TESTING"), ema.endpoints()]);
    expect(results[0]).toEqual([
      {
        id: row.EndpointId,
        hostname: "TESTING",
        groupId: null,
        groupName: null,
        agentConnected: true,
        ciraConnected: false,
        amtVersionValid: null,
        amtControlMode: null,
        amtProvisioningState: null,
        powerState: null,
      },
    ]);
    expect(request.mock.calls.filter(([url]) => new URL(String(url)).pathname === "/api/token")).toHaveLength(
      1,
    );
    const reads = request.mock.calls.filter(([url]) => new URL(String(url)).pathname !== "/api/token");
    expect(new URL(String(reads[0]?.[0])).searchParams.get("computerName")).toBe("TESTING");
    for (const [, init] of reads) {
      expect(init?.method).toBe("GET");
      expect(init?.redirect).toBe("error");
      expect(init?.body).toBeUndefined();
    }
    expect(JSON.stringify(results)).not.toContain("private-");
  });

  test("refreshes a rejected token for a read exactly once", async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(auth())
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(auth())
      .mockResolvedValueOnce(new Response(null, { status: 401 }));
    await expect(new EmaClient(settings, request).endpoints()).rejects.toMatchObject({ httpStatus: 401 });
    expect(request).toHaveBeenCalledTimes(4);
  });

  test("preserves null capabilities and numeric AMT enums from the live EMA server", async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(auth())
      .mockResolvedValueOnce(
        Response.json([
          {
            ...row,
            IsConnected: null,
            IsCiraConnected: null,
            IsAmtVersionValid: null,
            AmtControlMode: 2,
            AmtProvisioningState: 0,
          },
        ]),
      );
    const endpoints = await new EmaClient(settings, request).endpoints();
    expect(endpoints[0]).toMatchObject({
      agentConnected: null,
      ciraConnected: null,
      amtVersionValid: null,
      amtControlMode: 2,
      amtProvisioningState: 0,
    });
  });

  test.each([
    { payload: [{ ...row, IsConnected: "true" }] },
    { payload: [{ ...row, EndpointId: "" }] },
    { payload: [row, row] },
    { payload: { unexpected: [] } },
  ])("fails closed for malformed or ambiguous endpoint records", async ({ payload }) => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(auth())
      .mockResolvedValueOnce(Response.json(payload));
    await expect(new EmaClient(settings, request).endpoints()).rejects.toBeInstanceOf(EmaUnavailable);
  });

  test("does not forward upstream response bodies, tokens or account details", async () => {
    const request = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response("private-password private-bearer", { status: 403 }));
    const error = await new EmaClient(settings, request).endpoints().catch((error: unknown) => error);
    expect(error).toBeInstanceOf(EmaUnavailable);
    expect(String(error)).toBe("Error: Intel EMA unavailable");
    expect(request).toHaveBeenCalledTimes(1);
  });

  test("rejects non-JSON and oversized responses without caching a token", async () => {
    for (const response of [
      new Response("<html>login</html>"),
      Response.json({ access_token: "x".repeat(70_000) }),
    ]) {
      const request = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(response)
        .mockResolvedValueOnce(auth())
        .mockResolvedValueOnce(Response.json([row]));
      const ema = new EmaClient(settings, request);
      await expect(ema.endpoints()).rejects.toBeInstanceOf(EmaUnavailable);
      expect(await ema.endpoints()).toHaveLength(1);
    }
  });
});
