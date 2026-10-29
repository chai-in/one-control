/** These management routes belong to the optional desktop-policies module. */
export const desktopRoutes = [
  "GET /v1/scopes/:id/desktop",
  "PUT /v1/scopes/:id/desktop/policies/:policyId",
  "DELETE /v1/scopes/:id/desktop/policies/:policyId",
  "GET /v1/scopes/:id/desktop/policies/:policyId/versions",
  "POST /v1/scopes/:id/desktop/policies/:policyId/clone",
  "POST /v1/scopes/:id/desktop/policies/:policyId/rollback",
  "PUT /v1/scopes/:id/desktop/groups/:groupId",
  "DELETE /v1/scopes/:id/desktop/groups/:groupId",
  "PUT /v1/scopes/:id/desktop/assignments",
  "PUT /v1/scopes/:id/desktop/default-policy",
  "GET /v1/scopes/:id/desktop/devices/:deviceId/policy",
  "POST /v1/scopes/:id/desktop/policies/:policyId/canaries",
  "POST /v1/scopes/:id/desktop/canaries/:canaryId/abort",
  "POST /v1/scopes/:id/desktop/canaries/:canaryId/promote",
] as const;
