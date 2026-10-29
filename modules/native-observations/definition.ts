export const definition = {
  id: "native-observations",
  dependencies: [],
  permissions: [],
  routes: [
    "POST /v1/agent/native-report",
    "GET /v1/agent/native-report-state",
    "GET /v1/scopes/:id/native-observations",
  ],
};
