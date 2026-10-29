export const definition = {
  id: "recovery-escrow",
  dependencies: ["desktop-policies"],
  permissions: ["bitlocker.escrow"],
  routes: [
    "POST /v1/agent/native-recovery-key",
    "GET /v1/scopes/:id/recovery-keys",
    "POST /v1/scopes/:id/recovery-keys/:keyId/reveal",
  ],
};
