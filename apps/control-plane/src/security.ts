import { constants, createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { manifestSchema, type SignedEnvelope } from "@one-control/protocol";
import type { FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Config } from "./config.js";

export class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
  ) {
    super(code);
  }
}
export const hash = (value: string): string => createHash("sha256").update(value).digest("hex");
export const secret = (): string => randomBytes(32).toString("base64url");
export interface Actor {
  id: string;
  issuer: string;
  roles: Set<"operator" | "approver" | "viewer">;
  authenticationTime?: number | undefined;
  authenticationMethods?: string[] | undefined;
  authenticationContext?: string | undefined;
}
function equal(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(hash(left)), Buffer.from(hash(right)));
}
export function bearer(request: FastifyRequest): string {
  const auth = request.headers.authorization;
  if (!auth?.startsWith("Bearer ") || auth.length > 16_384) throw new ApiError(401, "unauthorized");
  return auth.slice(7);
}
export function administratorAuth(config: Config) {
  // Discovery is fixed to a trusted issuer. Never accept a JWKS URL from an incoming token.
  let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
  return async (request: FastifyRequest, role: "operator" | "approver" | "viewer"): Promise<Actor> => {
    const token = bearer(request);
    let actor: Actor;
    if (
      config.NODE_ENV !== "production" &&
      config.DEV_OPERATOR_TOKEN &&
      equal(token, config.DEV_OPERATOR_TOKEN)
    ) {
      actor = {
        id: "local-operator",
        issuer: "urn:one-control:local-development",
        roles: new Set(["operator", "viewer"]),
      };
    } else if (
      config.NODE_ENV !== "production" &&
      config.DEV_APPROVER_TOKEN &&
      equal(token, config.DEV_APPROVER_TOKEN)
    ) {
      actor = {
        id: "local-approver",
        issuer: "urn:one-control:local-development",
        roles: new Set(["approver", "viewer"]),
      };
    } else if (
      config.NODE_ENV !== "production" &&
      config.DEV_VIEWER_TOKEN &&
      equal(token, config.DEV_VIEWER_TOKEN)
    ) {
      actor = { id: "local-viewer", issuer: "urn:one-control:local-development", roles: new Set(["viewer"]) };
    } else {
      if (!config.OIDC_ISSUER || !config.OIDC_AUDIENCE) throw new ApiError(401, "unauthorized");
      if (!jwks) {
        const response = await fetch(
          new URL(".well-known/openid-configuration", `${config.OIDC_ISSUER.replace(/\/$/, "")}/`),
          { signal: AbortSignal.timeout(5000), redirect: "error" },
        );
        if (!response.ok) throw new ApiError(503, "identity_provider_unavailable");
        const discovery = (await response.json()) as { issuer: string; jwks_uri: string };
        if (discovery.issuer !== config.OIDC_ISSUER || !discovery.jwks_uri?.startsWith("https://"))
          throw new ApiError(503, "invalid_identity_discovery");
        jwks = createRemoteJWKSet(new URL(discovery.jwks_uri), { timeoutDuration: 5000 });
      }
      let subject: string;
      let authenticationTime: number | undefined;
      let authenticationMethods: string[] | undefined;
      let authenticationContext: string | undefined;
      try {
        const { payload } = await jwtVerify(token, jwks, {
          issuer: config.OIDC_ISSUER,
          audience: config.OIDC_AUDIENCE,
          algorithms: ["RS256", "ES256"],
          requiredClaims: ["sub", "exp", "iat"],
          maxTokenAge: "1h",
        });
        if (!payload.sub) throw new Error("missing subject");
        subject = payload.sub;
        if (typeof payload.auth_time === "number" && Number.isSafeInteger(payload.auth_time))
          authenticationTime = payload.auth_time;
        if (Array.isArray(payload.amr) && payload.amr.every((value) => typeof value === "string"))
          authenticationMethods = payload.amr;
        if (typeof payload.acr === "string") authenticationContext = payload.acr;
      } catch {
        throw new ApiError(401, "unauthorized");
      }
      const roles = new Set<"operator" | "approver" | "viewer">();
      if (config.OPERATOR_SUBJECTS.split(",").includes(subject)) roles.add("operator");
      if (config.APPROVER_SUBJECTS.split(",").includes(subject)) roles.add("approver");
      if (config.VIEWER_SUBJECTS.split(",").includes(subject) || roles.size > 0) roles.add("viewer");
      actor = {
        id: subject,
        issuer: config.OIDC_ISSUER,
        roles,
        authenticationTime,
        authenticationMethods,
        authenticationContext,
      };
    }
    if (!actor.roles.has(role)) throw new ApiError(403, "forbidden");
    return actor;
  };
}
export function verifyRelease(envelope: SignedEnvelope, config: Config) {
  if (!config.RELEASE_PUBLIC_KEY_FILE) throw new ApiError(503, "release_trust_unconfigured");
  const bytes = Buffer.from(envelope.payload, "base64");
  if (!bytes.length || bytes.length > 8192 || bytes.toString("base64") !== envelope.payload)
    throw new ApiError(400, "invalid_release_encoding");
  const key = createPublicKey(readFileSync(config.RELEASE_PUBLIC_KEY_FILE));
  if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 3072)
    throw new ApiError(503, "release_key_invalid");
  const valid = verify(
    "sha256",
    bytes,
    { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
    Buffer.from(envelope.signature, "base64"),
  );
  if (!valid) throw new ApiError(400, "invalid_release_signature");
  const manifest = manifestSchema.parse(JSON.parse(bytes.toString("utf8")));
  if (Date.parse(manifest.expiresAt) <= Date.now()) throw new ApiError(400, "release_expired");
  const url = new URL(manifest.artifactUrl);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    (url.port && url.port !== "443") ||
    !config.ARTIFACT_HOSTS.split(",").includes(url.hostname) ||
    !url.pathname.toLowerCase().endsWith(".msi")
  )
    throw new ApiError(400, "artifact_origin_forbidden");
  return manifest;
}
