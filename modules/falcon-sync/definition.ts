export const definition = {
  id: "falcon-sync",
  dependencies: ["falcon"],
  permissions: ["falcon.sync"],
  routes: [
    "GET /v1/scopes/:id/falcon-sync",
    "POST /v1/scopes/:id/falcon-sync/:resource",
    "GET /v1/scopes/:id/falcon-cache/:resource",
  ],
};
