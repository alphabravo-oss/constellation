// Separate Vitest config so it doesn't try to execute Playwright e2e/* files. Vitest looks for
// vitest.config.* first; otherwise it falls back to vite.config.* which runs everything.
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["e2e/**", "node_modules/**", "dist/**"],
    environment: "happy-dom",
  },
});
