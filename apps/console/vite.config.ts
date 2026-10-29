import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const origin = process.env.ONE_CONTROL_DEV_API_ORIGIN ?? "http://127.0.0.1:4317";
const api = new URL(origin);
if (
  api.protocol !== "http:" ||
  api.hostname !== "127.0.0.1" ||
  api.username ||
  api.password ||
  api.pathname !== "/" ||
  api.search ||
  api.hash
)
  throw new Error("The development API proxy must use an HTTP IPv4 loopback origin");
export default defineConfig({
  plugins: [react()],
  server: { strictPort: true, proxy: { "/v1": origin, "/health": origin } },
});
