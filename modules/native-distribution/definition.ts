export const definition = {
  id: "native-distribution",
  dependencies: [],
  permissions: ["native.distribute"],
  routes: [
    "GET /v1/scopes/:id/native-modules",
    "POST /v1/scopes/:id/native-modules/catalog",
    "PUT /v1/scopes/:id/native-modules/selection",
    "POST /v1/agent/native-configuration",
    "POST /v1/agent/native-artifact-ticket",
  ],
};
