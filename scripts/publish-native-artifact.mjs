import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { build: { type: "string" }, store: { type: "string" } } });
if (!values.build || !values.store || !isAbsolute(values.store))
  throw new Error("Explicit build and absolute protected artifact store required");
const directory = resolve(values.build);
const root = await realpath(values.store);
const build = JSON.parse(await readFile(join(directory, "build.json"), "utf8"));
const signed = JSON.parse(await readFile(join(directory, "signed-module.json"), "utf8"));
const artifact = signed.entry.manifest.artifacts[build.platform];
if (
  !/^[a-f0-9]{64}$/.test(build.sha256) ||
  !/^[a-z0-9.-]+\.zip$/.test(build.archive) ||
  artifact?.sha256 !== build.sha256 ||
  artifact?.size !== build.size
)
  throw new Error("Signed module and build identity differ");
const source = join(directory, build.archive);
const data = await readFile(source);
if (data.length !== build.size || createHash("sha256").update(data).digest("hex") !== build.sha256)
  throw new Error("Artifact bytes differ from their signed identity");
let parent = root;
for (const part of ["artifacts", build.sha256]) {
  parent = join(parent, part);
  try {
    await mkdir(parent);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  if (
    !(await lstat(parent)).isDirectory() ||
    (await lstat(parent)).isSymbolicLink() ||
    (await realpath(parent)) !== parent
  )
    throw new Error("Artifact publication directory is not ordinary protected storage");
}
const target = join(parent, "package.zip");
// Exclusive creation prevents a second publication replacing live immutable bytes.
const handle = await open(target, "wx", 0o640);
try {
  await handle.writeFile(data);
  await handle.sync();
} finally {
  await handle.close();
}
process.stdout.write(`Published immutable artifact ${build.sha256} (${build.size} bytes).\n`);
