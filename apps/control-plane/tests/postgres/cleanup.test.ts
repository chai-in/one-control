import { expect, test } from "vitest";
import { type CleanupObservation, withCleanup } from "./cleanup.js";

test.each([undefined, null, false, 0, "", { primary: true }, new Error("primary")])(
  "test cleanup preserves exact primary value %j while attempting every owner",
  async (primary) => {
    const calls: string[] = [];
    let observed: CleanupObservation | undefined;
    let rejected = false;
    try {
      await withCleanup(
        async (own) => {
          own("fixture", async () => {
            calls.push("fixture");
          });
          own("setup", async () => {
            calls.push("setup");
            throw new Error("secondary");
          });
          own("runtime", async () => {
            calls.push("runtime");
            throw new Error("secondary");
          });
          throw primary;
        },
        async (value) => {
          observed = value;
        },
      );
    } catch (error) {
      rejected = true;
      expect(error).toBe(primary);
    }
    expect(rejected).toBe(true);
    expect(calls).toEqual(["runtime", "setup", "fixture"]);
    expect(observed).toEqual({ result: "failed", attempted: calls, failed: ["runtime", "setup"] });
  },
);
test("successful test fails on cleanup failure after attempting its remaining owners", async () => {
  const calls: string[] = [];
  await expect(
    withCleanup(async (own) => {
      own("fixture", async () => {
        calls.push("fixture");
      });
      own("proxy", async () => {
        calls.push("proxy");
      });
      own("runtime", async () => {
        calls.push("runtime");
        throw new Error("secondary");
      });
      return 1;
    }),
  ).rejects.toThrow(AggregateError);
  expect(calls).toEqual(["runtime", "proxy", "fixture"]);
});
test("partial acquisition closes owners already admitted and a proof-write failure cannot replace primary", async () => {
  const primary = { acquisition: true };
  const calls: string[] = [];
  await expect(
    withCleanup(
      async (own) => {
        own("fixture", async () => {
          calls.push("fixture");
        });
        own("proxy", async () => {
          calls.push("proxy");
        });
        throw primary;
      },
      async () => {
        throw new Error("proof failure");
      },
    ),
  ).rejects.toBe(primary);
  expect(calls).toEqual(["proxy", "fixture"]);
});
test("proof-write failure fails an otherwise successful test", async () => {
  const primary = new Error("proof failure");
  await expect(
    withCleanup(
      async () => 1,
      async () => {
        throw primary;
      },
    ),
  ).rejects.toBe(primary);
});
