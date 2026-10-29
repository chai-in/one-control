export const definition = {
  id: "native-dispatch",
  dependencies: ["native-distribution"],
  permissions: [],
  routes: [
    "POST /v1/agent/native-claim",
    "GET /v1/agent/native-claims/:id",
    "POST /v1/agent/native-jobs/:id/renew",
    "POST /v1/agent/native-jobs/:id/report",
  ],
};
