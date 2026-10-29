export type PrimaryFailure = { failed: false } | { failed: true; error: unknown };

export async function finishCleanup(
  primary: PrimaryFailure,
  actions: readonly (() => Promise<unknown>)[],
): Promise<void> {
  let failure = primary;
  for (const action of actions) {
    try {
      await action();
    } catch (error) {
      if (!failure.failed) failure = { failed: true, error };
    }
  }
  if (failure.failed) throw failure.error;
}
