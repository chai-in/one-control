export const definition = {
  id: "falcon",
  dependencies: ["integration-http"],
  permissions: ["falcon.read"],
  routes: [
    "GET /v1/integrations/falcon/capabilities",
    "GET /v1/integrations/falcon/inventory/:resource",
    "GET /v1/integrations/falcon/hosts/:aid/detail",
    "GET /v1/integrations/falcon/hosts/:aid/assessment",
  ],
};
