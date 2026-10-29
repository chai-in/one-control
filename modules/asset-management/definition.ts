export const definition = {
  id: "asset-management",
  dependencies: [],
  permissions: ["assets.manage"],
  routes: [
    "GET /v1/scopes/:id/assets",
    "PUT /v1/scopes/:id/assets/:assetId",
    "DELETE /v1/scopes/:id/assets/:assetId",
    "PUT /v1/scopes/:id/assets/:assetId/links/:source",
    "DELETE /v1/scopes/:id/assets/:assetId/links/:source",
    "PUT /v1/scopes/:id/people/:personId",
    "POST /v1/scopes/:id/people/:personId/offboard",
  ],
};
