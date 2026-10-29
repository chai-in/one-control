import { copyFile } from "node:fs/promises";

// TypeScript resolves validate.d.mts for types and does not emit its sibling
// runtime. Keep the exact byte parser with the compiled package entrypoint.
await copyFile(
  new URL("../src/validate.mjs", import.meta.url),
  new URL("../dist/validate.mjs", import.meta.url),
);
