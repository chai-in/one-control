import { authorizeRead } from "./policy.js";

interface StoredArtifact {
  size: number;
  body: ReadableStream<Uint8Array>;
}
export interface ArtifactEnvironment {
  ARTIFACT_PUBLIC_HOST: string;
  ARTIFACT_READ_KEY: string;
  ARTIFACT_NATIVE_PACKAGES_ENABLED?: string;
  ARTIFACTS: {
    head(key: string): Promise<{ size: number; body?: never } | null>;
    get(key: string, options?: { range: { offset: number; length: number } }): Promise<StoredArtifact | null>;
  };
}
const headers = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
function unavailable(status: number): Response {
  return new Response(null, { status, headers });
}

export async function serveArtifact(
  request: Request,
  env: ArtifactEnvironment,
  now = Date.now(),
): Promise<Response> {
  try {
    const read = await authorizeRead(
      request,
      env.ARTIFACT_PUBLIC_HOST,
      env.ARTIFACT_READ_KEY,
      now,
      env.ARTIFACT_NATIVE_PACKAGES_ENABLED === "true",
    );
    if (!read) return unavailable(404);
    // A native installer verifies the complete signed size/hash. Partial responses are unsupported.
    if (request.headers.has("range")) return unavailable(416);
    const object =
      request.method === "HEAD"
        ? await env.ARTIFACTS.head(read.key)
        : read.kind === "native-package"
          ? await env.ARTIFACTS.get(read.key, { range: { offset: 0, length: read.size + 1 } })
          : await env.ARTIFACTS.get(read.key);
    if (!object) return unavailable(404);
    if (!Number.isSafeInteger(object.size) || object.size !== read.size) {
      await object.body?.cancel();
      return unavailable(503);
    }
    if (request.method === "GET" && !object.body) return unavailable(503);
    return new Response(request.method === "GET" ? object.body : null, {
      headers: {
        ...headers,
        "Content-Type": read.contentType,
        "Content-Length": String(read.size),
        "Content-Disposition": `attachment; filename="${read.filename}"`,
      },
    });
  } catch {
    // Never log capability URLs, secrets, object names or provider exception data.
    return unavailable(503);
  }
}
export default { fetch: (request: Request, env: ArtifactEnvironment) => serveArtifact(request, env) };
