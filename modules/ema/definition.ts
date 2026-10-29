export const definition = {
  id: "ema",
  dependencies: ["integration-http"],
  permissions: ["ema.read"],
  routes: ["GET /v1/integrations/ema/endpoints"],
};
