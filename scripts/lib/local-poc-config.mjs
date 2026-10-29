import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

export const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const ports = Object.freeze({ apiPort: 4347, consolePort: 4348, websitePort: 4349, tlsPort: 4447 });
export function configuration(root, value, env) {
  if (
    !isAbsolute(root) ||
    value.schemaVersion !== 1 ||
    value.root !== root ||
    value.repoRoot !== repository ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value.id)
  )
    throw new Error("Invalid local POC configuration");
  const configuredPorts = [value.apiPort, value.consolePort, value.websitePort, value.tlsPort];
  if (
    !configuredPorts.every((port) => Number.isInteger(port) && port >= 1024 && port <= 65535) ||
    new Set(configuredPorts).size !== configuredPorts.length
  )
    throw new Error("POC ports must be distinct non-privileged ports");
  if (!Object.entries(ports).every(([name, port]) => value[name] === port))
    throw new Error("This local POC uses its dedicated fixed ports");
  if (
    env.NODE_ENV !== "development" ||
    env.DEPLOYMENT_STAGE !== "poc" ||
    env.HOST !== "127.0.0.1" ||
    env.DATABASE_URL !== "local" ||
    env.PORT !== String(value.apiPort) ||
    env.LOCAL_DB_PATH !== join(root, "database")
  )
    throw new Error("POC requires an isolated loopback development database");
  const tokens = [env.DEV_OPERATOR_TOKEN, env.DEV_APPROVER_TOKEN, env.DEV_VIEWER_TOKEN];
  if (!tokens.every((token) => /^[A-Za-z0-9_-]{43}$/.test(token ?? "")) || new Set(tokens).size !== 3)
    throw new Error("POC roles require separate credentials");
  const allowed = new Set([
    "NODE_ENV",
    "DEPLOYMENT_STAGE",
    "POC_DEVICE_LIMIT",
    "HOST",
    "PORT",
    "DATABASE_URL",
    "LOCAL_DB_PATH",
    "DEV_OPERATOR_TOKEN",
    "DEV_APPROVER_TOKEN",
    "DEV_VIEWER_TOKEN",
    "RELEASE_PUBLIC_KEY_FILE",
    "ARTIFACT_HOSTS",
  ]);
  if (Object.keys(env).some((key) => !allowed.has(key)) || env.POC_DEVICE_LIMIT !== "5")
    throw new Error("Unexpected local POC configuration");
  if (
    Boolean(env.RELEASE_PUBLIC_KEY_FILE) !== Boolean(env.ARTIFACT_HOSTS) ||
    (env.RELEASE_PUBLIC_KEY_FILE &&
      (env.RELEASE_PUBLIC_KEY_FILE !== join(root, "release-public.pem") ||
        !env.ARTIFACT_HOSTS.split(",").every((host) =>
          /^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(host),
        )))
  )
    throw new Error("Local release trust must use its public key and explicit artifact hosts");
  return value;
}
export function load(root) {
  root = resolve(root);
  const settings = JSON.parse(readFileSync(join(root, "workspace.json"), "utf8").replace(/^\uFEFF/, ""));
  const env = parseEnv(readFileSync(join(root, "backend.env"), "utf8"));
  return { root, settings: configuration(root, settings, env), env };
}
export function loadSettings(root) {
  return JSON.parse(readFileSync(join(resolve(root), "workspace.json"), "utf8").replace(/^\uFEFF/, ""));
}
export function systemEnvironment(source = process.env) {
  const keep = new Set([
    "systemroot",
    "systemdrive",
    "windir",
    "temp",
    "tmp",
    "path",
    "pathext",
    "comspec",
    "userprofile",
    "appdata",
    "localappdata",
    "programdata",
    "username",
    "userdomain",
    "homedrive",
    "homepath",
    "processor_architecture",
    "number_of_processors",
  ]);
  return Object.fromEntries(Object.entries(source).filter(([key]) => keep.has(key.toLowerCase())));
}
