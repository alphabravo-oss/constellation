import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Dev-server proxy target. The SPA always calls same-origin `/api/v1`, so the dev server (and
// `vite preview`, which inherits `server.proxy`) forwards to the Go API. Default matches the
// `make dev` API port.
const apiURL = process.env.VITE_API_URL ?? "http://127.0.0.1:18080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Build metadata, stamped by the Makefile (VERSION/COMMIT/DATE) and read via src/lib/build-info.ts.
  define: {
    __APP_VERSION__: JSON.stringify(process.env.VERSION || "dev"),
    __APP_COMMIT__: JSON.stringify(process.env.COMMIT || ""),
    __APP_BUILD_DATE__: JSON.stringify(process.env.DATE || new Date().toISOString()),
  },
  build: {
    // /assets is an application route. Keep compiled files in a distinct
    // namespace so production nginx can serve direct asset-detail navigation.
    assetsDir: "static",
    // Let the bundler preserve route boundaries. Forced global vendor groups
    // pulled the editor, graph and chart dependencies into the entry preload graph.
    manifest: true,
  },
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: Number(process.env.VITE_PORT ?? 5173),
    strictPort: true,
    // Playwright writes traces/screenshots under the frontend: never reload the
    // dev page mid-test because of them.
    watch: { ignored: ["**/test-results/**", "**/playwright-report/**", "**/e2e/**", "**/.playwright-auth/**"] },
    proxy: {
      "/api": apiURL,
      "/openapi.json": apiURL,
      "/ws": { target: apiURL, ws: true },
    },
  },
});
