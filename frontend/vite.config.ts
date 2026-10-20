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
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "vendor-react",
              test: /node_modules[\\/](react|react-dom)[\\/]/,
              priority: 50,
            },
            {
              name: "vendor-editor",
              test: /node_modules[\\/](@monaco-editor|monaco-editor)[\\/]/,
              priority: 45,
            },
            {
              name: "vendor-graph",
              test: /node_modules[\\/]@xyflow[\\/]/,
              priority: 40,
            },
            {
              name: "vendor-charts",
              test: /node_modules[\\/](recharts|recharts-scale|d3-[^\\/]+)[\\/]/,
              priority: 35,
            },
            {
              name: "vendor-data",
              test: /node_modules[\\/](@tanstack|axios|date-fns|react-hook-form|@hookform)[\\/]/,
              priority: 30,
            },
            {
              name: "vendor-ui",
              test: /node_modules[\\/](@radix-ui|cmdk|lucide-react|class-variance-authority|clsx|tailwind-merge|sonner)[\\/]/,
              priority: 25,
            },
            {
              name: "vendor",
              test: /node_modules[\\/]/,
              priority: 1,
              maxSize: 450_000,
            },
          ],
        },
      },
    },
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
    proxy: {
      "/api": apiURL,
      "/openapi.json": apiURL,
      "/ws": { target: apiURL, ws: true },
    },
  },
});
