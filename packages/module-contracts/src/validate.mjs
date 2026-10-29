import schema from "../schema/wire.json" with { type: "json" };

export class WireError extends Error {
  code = "invalid_wire";
  constructor(path = "") {
    super(`invalid_wire: ${path}`);
  }
}
class NumericToken {
  constructor(token) {
    this.numberToken = token;
  }
}
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
// This parser retains original bytes for the caller. Its only output is a
// validated value; signatures must be checked against the original byte array.
export function parseWire(model, raw) {
  if (!(raw instanceof Uint8Array) || raw.length > 6291456) throw new WireError();
  let text;
  try {
    text = decoder.decode(raw);
  } catch {
    throw new WireError();
  }
  let at = 0;
  function whitespace() {
    while (/[\t\r\n ]/.test(text[at] ?? "!") && at < text.length) at++;
  }
  function string() {
    const start = at++;
    let closed = false;
    while (at < text.length) {
      const char = text[at++];
      if (char === '"') {
        closed = true;
        break;
      }
      if (char === "\\") at++;
    }
    if (!closed) throw new WireError();
    let value;
    try {
      value = JSON.parse(text.slice(start, at));
    } catch {
      throw new WireError();
    }
    for (let i = 0; i < value.length; i++) {
      const n = value.charCodeAt(i);
      if (n >= 0xd800 && n <= 0xdbff) {
        const low = value.charCodeAt(++i);
        if (!(low >= 0xdc00 && low <= 0xdfff)) throw new WireError();
      } else if (n >= 0xdc00 && n <= 0xdfff) throw new WireError();
    }
    return value;
  }
  function value(depth = 0) {
    if (depth > 64) throw new WireError();
    whitespace();
    const char = text[at];
    if (char === '"') return string();
    if (char === "{") {
      at++;
      const result = Object.create(null);
      whitespace();
      if (text[at] === "}") {
        at++;
        return result;
      }
      for (;;) {
        whitespace();
        if (text[at] !== '"') throw new WireError();
        const key = string();
        if (Object.hasOwn(result, key)) throw new WireError();
        whitespace();
        if (text[at++] !== ":") throw new WireError();
        result[key] = value(depth + 1);
        whitespace();
        const separator = text[at++];
        if (separator === "}") return result;
        if (separator !== ",") throw new WireError();
      }
    }
    if (char === "[") {
      at++;
      const result = [];
      whitespace();
      if (text[at] === "]") {
        at++;
        return result;
      }
      for (;;) {
        result.push(value(depth + 1));
        whitespace();
        const separator = text[at++];
        if (separator === "]") return result;
        if (separator !== ",") throw new WireError();
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(
      text.slice(at),
    );
    if (!match) throw new WireError();
    at += match[0].length;
    if (/^-?\d/.test(match[0])) return new NumericToken(match[0]);
    return JSON.parse(match[0]);
  }
  let result;
  try {
    result = value();
    whitespace();
    if (at !== text.length) throw new WireError();
    validate(model, result, "");
  } catch (error) {
    if (error instanceof WireError) throw error;
    throw new WireError();
  }
  return JSON.parse(text);
}
function validArtifactURL(value) {
  const parts =
    /^https:\/\/(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?(\/[a-z0-9._~!$&'()*+,;=:@%/-]*)?(\?[a-z0-9._~!$&'()*+,;=:@%/?-]*)?$/i.exec(
      value,
    );
  if (!parts || parts[0] !== value || /%(?![0-9a-f]{2})/i.test(value)) return false;
  const host = parts[1] ?? "";
  if (parts[2] && Number(parts[2]) > 65535) return false;
  if (host.startsWith("[")) {
    try {
      new URL(`https://${host}`);
      return true;
    } catch {
      return false;
    }
  }
  const dns = host.endsWith(".") ? host.slice(0, -1) : host;
  if (
    dns.length > 253 ||
    !dns.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
  )
    return false;
  const last = dns.slice(dns.lastIndexOf(".") + 1);
  if (/^(?:[0-9]+|0x[0-9a-f]*)$/i.test(last)) {
    return (
      host === dns &&
      host.split(".").length === 4 &&
      host.split(".").every((part) => /^(?:0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255)
    );
  }
  return true;
}
function validate(kind, value, path) {
  const fail = () => {
    throw new WireError(path);
  };
  const fields = schema.types[kind];
  if (fields) {
    if (
      value === null ||
      Array.isArray(value) ||
      typeof value !== "object" ||
      Object.hasOwn(value, "numberToken")
    )
      fail();
    for (const key of Object.keys(value))
      if (!Object.hasOwn(fields, key) && !Object.hasOwn(fields, `${key}?`)) fail();
    for (const [raw, type] of Object.entries(fields)) {
      const optional = raw.endsWith("?");
      const key = raw.replace(/\?$/, "");
      if (!Object.hasOwn(value, key)) {
        if (!optional) fail();
      } else validate(type, value[key], `${path}/${key}`);
    }
    if (kind === "Scope") {
      for (const key of ["principal", "sessionId", "sessionIncarnation", "localNonce"])
        if (Object.hasOwn(value, key) !== (value.kind === "user")) fail();
    }
    if (
      kind === "Manifest" &&
      (value.permissions.length > 32 || new Set(value.permissions).size !== value.permissions.length)
    )
      fail();
    return;
  }
  if (kind.startsWith("array:")) {
    if (!Array.isArray(value) || value.length > 512) fail();
    for (const [i, item] of value.entries()) validate(kind.slice(6), item, `${path}/${i}`);
    return;
  }
  if (kind.startsWith("map:") || kind.startsWith("platformmap:")) {
    if (value === null || Array.isArray(value) || typeof value !== "object") fail();
    if (Object.keys(value).length > 512 || (path.endsWith("/dependencies") && Object.keys(value).length > 32))
      fail();
    for (const [key, item] of Object.entries(value)) {
      if (kind.startsWith("platformmap:")) {
        if (!schema.platforms.includes(key)) fail();
      } else validate("id", key, path);
      validate(kind.slice(kind.indexOf(":") + 1), item, `${path}/${key}`);
    }
    return;
  }
  if (kind === "boolean") {
    if (typeof value !== "boolean") fail();
    return;
  }
  if (["timestamp", "size"].includes(kind) || /^literal:[0-9]+$/.test(kind)) {
    if (!(value instanceof NumericToken)) fail();
    const token = value.numberToken;
    if (typeof token !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(token)) fail();
    const n = Number(token);
    if (
      !Number.isSafeInteger(n) ||
      (kind === "timestamp" && n < 1) ||
      (kind === "size" && (n < 1 || n > 2147483648)) ||
      (kind.startsWith("literal:") && n !== Number(kind.slice(8)))
    )
      fail();
    return;
  }
  if (typeof value !== "string" || value.length > 6291456) fail();
  if (kind === "string") return;
  if (kind.startsWith("literal:")) {
    if (value !== kind.slice(8)) fail();
    return;
  }
  if (kind.startsWith("enum:")) {
    if (!kind.slice(5).split(",").includes(value)) fail();
    return;
  }
  if (kind === "platform") {
    if (!schema.platforms.includes(value)) fail();
    return;
  }
  if (kind === "domain") {
    if (!schema.domains.includes(value)) fail();
    return;
  }
  if (kind === "identity") {
    if (
      new TextEncoder().encode(value).length < 1 ||
      new TextEncoder().encode(value).length > 256 ||
      /[\0\r\n]/.test(value)
    )
      fail();
    return;
  }
  if (kind === "https") {
    if (!validArtifactURL(value)) fail();
    return;
  }
  if (!schema.patterns[kind] || !new RegExp(schema.patterns[kind]).test(value)) fail();
  if (kind === "id" && value.length > 96) fail();
  if (kind === "decimal" && BigInt(value) > 18446744073709551615n) fail();
  if (
    kind === "nonce" &&
    (Buffer.from(value, "base64url").length !== 32 ||
      Buffer.from(value, "base64url").toString("base64url") !== value)
  )
    fail();
}
