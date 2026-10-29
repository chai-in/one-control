import { readFileSync } from "node:fs";
import { parseEnv } from "node:util";

function loopbackOrigin(value) {
  const url = new URL(value);
  if (
    url.protocol !== "http:" ||
    url.hostname !== "127.0.0.1" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    !url.port ||
    Number(url.port) < 1024
  )
    throw new Error("Console acceptance requires explicit HTTP IPv4 loopback origins");
  return url.origin;
}
export const apiOrigin = loopbackOrigin(process.env.ONE_CONTROL_QA_API_ORIGIN ?? "http://127.0.0.1:4317");
export const consoleOrigin = loopbackOrigin(
  process.env.ONE_CONTROL_QA_CONSOLE_ORIGIN ?? "http://127.0.0.1:4318",
);
export const env = parseEnv(readFileSync(process.env.ONE_CONTROL_QA_ENV_FILE ?? ".env", "utf8"));
