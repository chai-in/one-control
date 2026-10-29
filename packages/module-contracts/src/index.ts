export { WireError } from "./validate.mjs";
export * from "./wire.generated.js";

import { parseWire as parse } from "./validate.mjs";
import type { WireModels } from "./wire.generated.js";

export function parseWire<M extends keyof WireModels>(model: M, raw: Uint8Array): WireModels[M] {
  return parse(model, raw) as WireModels[M];
}
