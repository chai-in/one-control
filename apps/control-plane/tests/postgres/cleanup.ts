type Stage = "fixture" | "proxy" | "runtime" | "setup";
export type CleanupObservation = {
  result: "passed" | "failed";
  attempted: Stage[];
  failed: Stage[];
};

export async function withCleanup<T>(
  work: (own: (stage: Stage, close: () => Promise<void>) => void) => Promise<T>,
  observe: (observation: CleanupObservation) => Promise<void> = async () => {},
): Promise<T> {
  const resources: Array<{ stage: Stage; close: () => Promise<void> }> = [];
  let outcome: { ok: true; value: T } | { ok: false; error: unknown };
  try {
    outcome = { ok: true, value: await work((stage, close) => resources.push({ stage, close })) };
  } catch (error) {
    outcome = { ok: false, error };
  }
  const observation: CleanupObservation = { result: "passed", attempted: [], failed: [] };
  for (const { stage, close } of resources.reverse()) {
    observation.attempted.push(stage);
    try {
      await close();
    } catch {
      observation.failed.push(stage);
      try {
        process.stderr.write(`PostgreSQL test cleanup failed (${stage})\n`);
      } catch {}
    }
  }
  if (!outcome.ok || observation.failed.length) observation.result = "failed";
  let proofFailure: { error: unknown } | undefined;
  try {
    await observe(observation);
  } catch (error) {
    proofFailure = { error };
    try {
      process.stderr.write("PostgreSQL test observation write failed\n");
    } catch {}
  }
  if (!outcome.ok) throw outcome.error;
  if (observation.failed.length)
    throw new AggregateError(
      observation.failed.map((stage) => new Error(`PostgreSQL test cleanup failed (${stage})`)),
      "PostgreSQL test cleanup failed",
    );
  if (proofFailure) throw proofFailure.error;
  return outcome.value;
}
