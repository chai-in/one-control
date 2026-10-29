import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";

if (existsSync(".env")) throw new Error(".env already exists; preserve existing credentials");
mkdirSync(".local", { recursive: true });
const token = () => randomBytes(32).toString("base64url");
writeFileSync(
  ".env",
  `NODE_ENV=development\nDEPLOYMENT_STAGE=poc\nPOC_DEVICE_LIMIT=5\nHOST=127.0.0.1\nPORT=4317\nDATABASE_URL=local\nDEV_OPERATOR_TOKEN=${token()}\nDEV_APPROVER_TOKEN=${token()}\nDEV_VIEWER_TOKEN=${token()}\n`,
  { mode: 0o600, flag: "wx" },
);
console.log(
  "Local configuration created in .env. Use its separate operator, approver and viewer credentials in the console. Keep it private.",
);
