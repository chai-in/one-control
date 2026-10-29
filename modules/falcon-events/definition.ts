export const definition = {
  id: "falcon-events",
  dependencies: ["falcon"],
  permissions: ["falcon.events"],
  routes: ["GET /v1/scopes/:id/falcon-events", "POST /v1/integrations/falcon/webhook"],
};
