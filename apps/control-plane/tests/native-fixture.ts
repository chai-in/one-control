import assert from "node:assert/strict";
import { constants, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance, InjectOptions } from "fastify";
import { nativeSigningBytes } from "../../../modules/native-distribution/server/signing.js";
import { hash } from "../src/security.js";
import { serverModules } from "../src/server-modules.js";

// Fresh, disposable signing custody. No installed authority or network artifact
// service is used: these tests exercise the actual publication and dispatch API.
export async function nativeFixture(
  operator: string,
  options: {
    features?: string[];
    artifactOrigin?: string;
    artifacts?: Record<
      string,
      { url: string; sha256: string; size: number; files: { path: string; sha256: string; size: number }[] }
    >;
  } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), "one-control-native-test-"));
  const scopeId = randomUUID();
  const artifactKey = randomBytes(32);
  const artifactKeyFile = join(directory, "artifact-read.key");
  await writeFile(artifactKeyFile, artifactKey, { mode: 0o600 });
  const headers = { authorization: `Bearer ${operator}` };
  const now = Math.floor(Date.now() / 1000);
  const artifactOrigin = options.artifactOrigin ?? "https://artifacts.example";
  const roles = ["catalog", "policy", "freshness", "publisher"] as const;
  const domains = [
    "module-catalog.v2",
    "device-policy.v1",
    "policy-freshness.v1",
    "publisher-attestation.v1",
  ];
  const pairs = roles.map(() => generateKeyPairSync("rsa", { modulusLength: 3072 }));
  const keys = roles.map((id, index) => ({
    id,
    role: domains[index],
    pem: pairs[index]!.publicKey.export({ type: "spki", format: "pem" }),
    notBefore: now - 60,
    notAfter: now + 86400,
  }));
  const signers: Record<string, { keyId: string; privateKeyFile: string }> = {};
  for (const [index, id] of roles.entries()) {
    if (id === "publisher") continue;
    const privateKeyFile = join(directory, `${id}.pem`);
    await writeFile(privateKeyFile, pairs[index]!.privateKey.export({ type: "pkcs8", format: "pem" }), {
      mode: 0o600,
    });
    signers[id] = { keyId: id, privateKeyFile };
  }
  const configuration = join(directory, "authority.json");
  await writeFile(
    configuration,
    JSON.stringify({
      custodyReference: randomUUID(),
      rootVersion: "1",
      authorityEpoch: "1",
      administrators: [{ issuer: "urn:one-control:local-development", subject: "local-operator" }],
      keys,
      signers,
      publishers: { fixture: ["publisher"] },
      artifactOrigins: [`${artifactOrigin}/`],
    }),
  );
  const permissions = [...new Set(serverModules.modules.flatMap((module) => [...module.permissions]))];
  const requestedFeatures = options.features ?? [
    "inventory",
    "windows-updates",
    "application-updates",
    "user-session-host",
    "store-updates",
    "deployment",
  ];
  const featureIds = [...new Set(requestedFeatures)];
  const attestations: string[] = [];
  const entries = featureIds.map((id) => {
    const artifact = options.artifacts?.[id] ?? {
      url: `${artifactOrigin}/v1/artifacts/${"a".repeat(64)}/package.zip`,
      sha256: "a".repeat(64),
      size: 100,
      files: [{ path: "bin/host.exe", sha256: "b".repeat(64), size: 10 }],
    };
    const payload = Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        id,
        version: "0.1.0",
        platform: "win-x64",
        publisher: "fixture",
        layout: "native-host-v1",
        archiveSha256: artifact.sha256,
        archiveSize: artifact.size,
        files: artifact.files,
        issuedAt: now - 1,
        expiresAt: now + 7200,
      }),
    );
    const protectedBytes = Buffer.from(
      JSON.stringify({
        schemaVersion: 1,
        domain: "publisher-attestation.v1",
        alg: "PS256",
        rootVersion: "1",
        keyId: "publisher",
      }),
    );
    const signature = sign("sha256", nativeSigningBytes("publisher", protectedBytes, payload), {
      key: pairs[3]!.privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
    const envelope = JSON.stringify({
      protected: protectedBytes.toString("base64url"),
      payload: payload.toString("base64url"),
      signature: signature.toString("base64url"),
    });
    attestations.push(Buffer.from(envelope).toString("base64url"));
    return {
      manifest: {
        schemaVersion: 1,
        id,
        version: "0.1.0",
        kind: "feature",
        minimumBootstrap: "0.1.0",
        permissions: [...serverModules.modules.find((module) => module.id === id)!.permissions],
        dependencies: {},
        artifacts: {
          "win-x64": {
            url: artifact.url,
            sha256: artifact.sha256,
            size: artifact.size,
          },
        },
      },
      platforms: {
        "win-x64": {
          publisher: "fixture",
          layout: "native-host-v1",
          hostAbi: "one-control-host-v1",
          scope: "machine",
          attestationSha256: hash(envelope),
        },
      },
    };
  });
  const policies = new Map<string, string>();
  const claims = new Map<string, string>();
  async function checked(app: FastifyInstance, options: InjectOptions, code = 200) {
    const response = await app.inject(options);
    assert.equal(response.statusCode, code, response.body);
    return response.json();
  }
  async function version(app: FastifyInstance) {
    return (await checked(app, { url: `/v1/scopes/${scopeId}/modules`, headers })).version as string;
  }
  return {
    scopeId,
    artifactKey: artifactKey.toString("base64url"),
    installationTrust: {
      keys,
      rootVersion: "1",
      authorityEpoch: "1",
      publishers: { fixture: ["publisher"] },
      artifactOrigins: [artifactOrigin],
    },
    config: {
      NATIVE_AUTHORITY_CONFIG: configuration,
      CREDENTIAL_ROOT: directory,
      ARTIFACT_READ_KEY_FILE: artifactKeyFile,
      EMA_MANAGEMENT_SCOPE: scopeId,
    },
    async close() {
      await rm(directory, { recursive: true, force: true });
    },
    async prepare(app: FastifyInstance) {
      await checked(app, {
        method: "POST",
        url: "/v1/authority/native-custody/activate",
        headers,
        payload: {},
      });
      await checked(
        app,
        {
          method: "POST",
          url: "/v1/scopes",
          headers,
          payload: { id: scopeId, name: "Native API fixture", kind: "company" },
        },
        201,
      );
      await checked(app, {
        method: "PUT",
        url: `/v1/scopes/${scopeId}/permissions`,
        headers,
        payload: { expectedVersion: await version(app), permissions },
      });
      await checked(app, {
        method: "PUT",
        url: `/v1/scopes/${scopeId}/grants`,
        headers,
        payload: {
          expectedVersion: await version(app),
          issuer: "urn:one-control:local-development",
          subject: "local-approver",
          permission: "approve",
          enabled: true,
        },
      });
      await checked(app, {
        method: "PUT",
        url: `/v1/scopes/${scopeId}/server-modules`,
        headers,
        payload: {
          expectedVersion: await version(app),
          enabled: [...featureIds, "native-distribution", "native-dispatch", "native-observations", "ema"],
        },
      });
      const catalog = await checked(app, {
        method: "POST",
        url: `/v1/scopes/${scopeId}/native-modules/catalog`,
        headers,
        payload: {
          requestId: randomUUID(),
          expectedVersion: await version(app),
          entries,
          attestations,
          lifetimeSeconds: 3600,
        },
      });
      await checked(app, {
        method: "PUT",
        url: `/v1/scopes/${scopeId}/native-modules/selection`,
        headers,
        payload: {
          expectedVersion: await version(app),
          platform: "win-x64",
          catalogId: catalog.publicationId,
          enabled: Object.fromEntries(featureIds.map((id) => [id, "0.1.0"])),
          disabled: [],
          allowedPermissions: permissions,
          bootstrapVersion: "0.1.0",
        },
      });
    },
    async enroll(app: FastifyInstance, hostname = "native-test-workstation", invitationToken?: string) {
      const token = invitationToken ?? randomBytes(32).toString("base64url");
      const credential = randomBytes(32).toString("base64url");
      if (!invitationToken)
        await checked(
          app,
          {
            method: "POST",
            url: `/v1/scopes/${scopeId}/native-invitations`,
            headers,
            payload: {
              tokenHash: hash(token),
              hostname,
              platform: "win-x64",
              machineId: `windows:${randomUUID()}`,
            },
          },
          201,
        );
      const enrolled = await checked(
        app,
        {
          method: "POST",
          url: "/v1/agent/native-enroll",
          payload: { token, credentialHash: hash(credential) },
        },
        201,
      );
      const configuration = await checked(app, {
        method: "POST",
        url: "/v1/agent/native-configuration",
        headers: { authorization: `Bearer ${credential}` },
        payload: { nonce: randomBytes(32).toString("base64url") },
      });
      const envelope = JSON.parse(Buffer.from(configuration.policy, "base64url").toString("utf8"));
      policies.set(credential, hash(Buffer.from(envelope.payload, "base64url").toString("utf8")));
      return { ...enrolled, credential } as { deviceId: string; enrollmentId: string; credential: string };
    },
    async inject(app: FastifyInstance, options: InjectOptions) {
      const url = String(options.url);
      const credential = String((options.headers as Record<string, string>)?.authorization ?? "").replace(
        /^Bearer /,
        "",
      );
      const policyDigest = policies.get(credential);
      const payload = { ...(options.payload as Record<string, unknown>) };
      let leaseToken: string | undefined;
      if (url === "/v1/agent/native-claim") {
        leaseToken = randomBytes(32).toString("base64url");
        Object.assign(payload, { requestId: randomUUID(), leaseTokenHash: hash(leaseToken), policyDigest });
      } else if (/\/v1\/agent\/native-jobs\/[^/]+\/(renew|report)$/.test(url)) {
        payload.claimId = claims.get(url.split("/")[4]!);
        if (url.endsWith("/renew")) payload.policyDigest = policyDigest;
      }
      const response = await app.inject({
        ...options,
        ...(url.startsWith("/v1/agent/native-") ? { payload } : {}),
      });
      const data = response.json();
      if (leaseToken && data.lease) {
        assert.equal(response.body.includes(leaseToken), false);
        claims.set(data.lease.id, data.lease.claimId);
        // The client chose this secret before the POST; the server never returns it.
        data.lease.leaseToken = leaseToken;
      }
      return { statusCode: response.statusCode, body: response.body, json: () => data };
    },
  };
}
