import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Local dev: backend at http://localhost:8000.
// Docker dev: compose sets VITE_API_PROXY_TARGET=http://backend:8000.
const apiTarget = process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": apiTarget,
    },
  },
});
