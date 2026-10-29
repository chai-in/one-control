import { constants, createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { manifestSchema } from "@one-control/protocol";

const [manifestFile, privateKeyFile, outputFile] = process.argv.slice(2);
if (!manifestFile || !privateKeyFile || !outputFile || process.argv.length !== 5)
  throw new Error("Usage: node scripts/sign-release.mjs manifest.json offline-private.pem envelope.json");
const manifest = manifestSchema.parse(JSON.parse(readFileSync(manifestFile, "utf8")));
if (Date.parse(manifest.expiresAt) <= Date.now()) throw new Error("Metadata already expired");
const key = createPrivateKey(readFileSync(privateKeyFile));
if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 3072)
  throw new Error("RSA key must be at least 3072 bits");
const payload = Buffer.from(JSON.stringify(manifest), "utf8");
const signature = sign("sha256", payload, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
writeFileSync(
  outputFile,
  JSON.stringify({ payload: payload.toString("base64"), signature: signature.toString("base64") }, null, 2),
  { flag: "wx" },
);
console.log("Signed envelope written. Keep the private key offline and outside the repository.");
