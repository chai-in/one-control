import type { Job } from "@one-control/protocol";
import { userSessionSchema } from "@one-control/protocol";
import { record, text } from "../../../apps/console/src/view-model.js";

export function sessionChoices(jobs: Job[], deviceIds: string[], now = Date.now()) {
  if (deviceIds.length !== 1) return [];
  const latest = jobs
    .filter(
      (job) => job.device_id === deviceIds[0] && job.kind === "sessions.list" && job.state === "succeeded",
    )
    .sort((a, b) => Date.parse(b.finished_at ?? "") - Date.parse(a.finished_at ?? ""))[0];
  if (
    !latest ||
    !latest.finished_at ||
    now - Date.parse(latest.finished_at) > 300000 ||
    latest.result?.partial === true ||
    !Array.isArray(latest.result?.sessions)
  )
    return [];
  return latest.result.sessions
    .map(record)
    .filter((value) => value?.selectable === true && value.state === "active")
    .flatMap((value) => {
      const parsed = userSessionSchema.safeParse({
        sessionId: value?.sessionId,
        userSid: value?.userSid,
        logonId: value?.logonId,
      });
      return parsed.success
        ? [
            {
              target: parsed.data,
              key: JSON.stringify(parsed.data),
              label: `${text(value?.domain)}\\${text(value?.user)} · ${text(value?.station)} (${parsed.data.sessionId})`,
            },
          ]
        : [];
    });
}
