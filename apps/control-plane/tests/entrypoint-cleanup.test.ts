import { expect, test } from "vitest";
import { finishCleanup } from "../src/entrypoint-cleanup.js";

test.each([undefined, null, false, 0, "", { arbitrary: true }])(
  "preserves exact primary %j and attempts all cleanup",
  async (error) => {
    const order: number[] = [];
    const result = await finishCleanup({ failed: true, error }, [
      async () => {
        order.push(1);
        throw new Error("cleanup");
      },
      async () => {
        order.push(2);
      },
    ]).then(
      () => ({ failed: false }),
      (caught: unknown) => ({ failed: true, error: caught }),
    );
    expect(result).toEqual({ failed: true, error });
    expect(order).toEqual([1, 2]);
  },
);
test("first cleanup failure survives later failures", async () => {
  const first = {};
  await expect(
    finishCleanup({ failed: false }, [
      async () => {
        throw first;
      },
      async () => {
        throw null;
      },
    ]),
  ).rejects.toBe(first);
});
