import { constants, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";

function frame(keyId, protectedBytes, payload) {
  const parts = [Buffer.from("ONECONTROL-SIGNED-V1\n")];
  for (const part of [Buffer.from(keyId), protectedBytes, payload]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(part.length);
    parts.push(length, part);
  }
  return Buffer.concat(parts);
}
if (process.argv.includes("--sign")) {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 3072,
    publicExponent: 65537,
  });
  const protectedBytes = Buffer.from(
    '{"schemaVersion":1,"domain":"device-policy.v1","alg":"PS256","rootVersion":"1","keyId":"policy"}',
  );
  const payload = Buffer.from('{"message":"exact bytes, including whitespace"}\n');
  const signature = sign("sha256", frame("policy", protectedBytes, payload), {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  console.log(
    JSON.stringify({
      publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      envelope: {
        protected: protectedBytes.toString("base64url"),
        payload: payload.toString("base64url"),
        signature: signature.toString("base64url"),
      },
    }),
  );
} else if (process.argv.includes("--verify")) {
  const { publicKey, envelope } = JSON.parse(readFileSync(0, "utf8"));
  const protectedBytes = Buffer.from(envelope.protected, "base64url");
  const payload = Buffer.from(envelope.payload, "base64url");
  const { keyId } = JSON.parse(protectedBytes);
  if (
    !verify(
      "sha256",
      frame(keyId, protectedBytes, payload),
      {
        key: Buffer.from(publicKey, "base64"),
        type: "spki",
        format: "der",
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      },
      Buffer.from(envelope.signature, "base64url"),
    )
  )
    process.exit(1);
  console.log('{"verified":true}');
} else throw new Error("Use --sign or --verify");
