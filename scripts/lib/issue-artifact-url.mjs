import { issueReadUrl } from "../../apps/artifacts/dist/policy.js";

// Called through the elevated Windows wrapper. Secrets travel only over inherited stdin/stdout pipes.
if (process.argv.length !== 2) throw new Error("Artifact URL issuer accepts protected stdin only");
const chunks = [];
let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.length;
  if (size > 8192) throw new Error("Artifact authorization input exceeds its size bound");
  chunks.push(chunk);
}
const input = JSON.parse(
  Buffer.concat(chunks)
    .toString("utf8")
    .replace(/^\uFEFF/, ""),
);
if (
  !input ||
  Object.keys(input).length !== 2 ||
  typeof input.secret !== "string" ||
  !input.artifact ||
  Object.keys(input.artifact).sort().join(",") !== "expires,origin,sha256,size,version"
)
  throw new Error("Invalid artifact authorization input");
const url = await issueReadUrl(input.artifact, input.secret, Date.now());
process.stdout.write(JSON.stringify({ url, ...input.artifact }));
