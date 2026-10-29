import type { WireModels } from "./wire.generated.js";

export class WireError extends Error {
  code: string;
  constructor(path?: string);
}
export function parseWire<M extends keyof WireModels>(model: M, raw: Uint8Array): WireModels[M];
