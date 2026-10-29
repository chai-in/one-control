import { buildApp } from "./app.js";
import { parseConfig } from "./config.js";
import { reconcileExpiredJobs } from "./coordinator.js";
import { migrate, openDatabase, TransactionCommitUnknownError } from "./database.js";
import { finishCleanup } from "./entrypoint-cleanup.js";
import { type BackupIdentity, createLocalBackup } from "./local-backup.js";

const config = parseConfig(process.env);
const db = await openDatabase(config.DATABASE_URL, config.LOCAL_DB_PATH);
// Called only by the inherited, local POC supervisor IPC. Never exposed as an HTTP route.
export async function captureLocalBackup(destination: string, identity: BackupIdentity) {
  if (stopping || config.DEPLOYMENT_STAGE !== "poc" || !db.snapshotLocal)
    throw new Error("Local backup unavailable");
  return createLocalBackup(db.snapshotLocal, destination, identity);
}
let stopping = false;
let sweep: Promise<unknown> | undefined;
let app: Awaited<ReturnType<typeof buildApp>> | undefined;
let timer: ReturnType<typeof setInterval> | undefined;
let shutdownPromise: Promise<void> | undefined;
function shutdown() {
  shutdownPromise ??= (async () => {
    stopping = true;
    clearInterval(timer);
    const outstandingSweep = sweep;
    await finishCleanup({ failed: false }, [
      async () => app?.close(),
      async () => outstandingSweep,
      () => db.close(),
    ]);
  })();
  return shutdownPromise;
}
try {
  if (config.NODE_ENV !== "production") await migrate(db);
  const activeApp = await buildApp(db, config);
  app = activeApp;
  timer = setInterval(() => {
    if (sweep || stopping) return;
    sweep = reconcileExpiredJobs(db)
      .catch((error: unknown) => {
        if (error instanceof TransactionCommitUnknownError)
          activeApp.log.error(
            { databaseOutcome: "unknown", retryAllowed: false },
            "Coordinator commit outcome is unknown; inspect current durable state",
          );
        else activeApp.log.error("Coordinator sweep failed; inspect current durable state");
      })
      .finally(() => {
        sweep = undefined;
      });
  }, 15_000);
  timer.unref();
  for (const signal of ["SIGINT", "SIGTERM"] as const)
    process.on(signal, () => {
      void shutdown().catch(() => {
        process.exitCode = 1;
      });
    });
  await activeApp.listen({ host: config.HOST, port: config.PORT });
} catch (error) {
  await finishCleanup({ failed: true, error }, [shutdown]);
}
