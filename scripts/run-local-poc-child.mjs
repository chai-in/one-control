import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { backupDirectory, backupId } from "./lib/local-poc-backup.mjs";
import { loadSettings, repository } from "./lib/local-poc-config.mjs";

if (!process.send || process.argv.length !== 5)
  throw new Error("POC child must be launched by its supervisor");
const role = process.argv[2];
const root = process.argv[3];
const runId = process.argv[4];
if (role !== "api" || !backupId.test(runId ?? ""))
  throw new Error("POC backend child requires its supervisor run identity");
const settings = loadSettings(root);
let close = async () => {};
let stopping = false;
let capture;
let backupWork;
async function stop() {
  if (stopping) return;
  stopping = true;
  await backupWork;
  await close();
  if (process.connected) process.disconnect();
}
process.on("message", (message) => {
  if (message === "one-control-poc:stop") void stop();
  else if (
    role === "api" &&
    !stopping &&
    capture &&
    !backupWork &&
    message?.type === "one-control-poc:backup" &&
    message.runId === runId &&
    backupId.test(message.requestId ?? "")
  ) {
    backupWork = Promise.resolve()
      .then(() => {
        const destination = join(backupDirectory(root, "backups"), message.requestId);
        return capture(destination, { workspaceId: settings.id, runId, requestId: message.requestId });
      })
      .catch(() => process.stderr.write("Local POC backup failed; preserve the claimed backup directory\n"))
      .finally(() => {
        backupWork = undefined;
        if (process.connected)
          process.send({ type: "one-control-poc:backup-finished", requestId: message.requestId });
      });
  }
});
process.on("disconnect", () => void stop());
process.on("SIGINT", () => void stop());
process.on("SIGTERM", () => void stop());
if (role === "api") {
  const backend = await import(
    pathToFileURL(join(repository, "apps/control-plane/dist/apps/control-plane/src/main.js")).href
  );
  capture = backend.captureLocalBackup;
  if (typeof capture !== "function")
    throw new Error("Build the matching POC backend before starting this supervisor");
  close = async () => {
    process.emit("SIGTERM");
  };
}
if (stopping) await close();
else process.send({ type: "ready", role });
