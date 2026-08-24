import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

const apiURL = process.env.VITE_API_URL ?? "http://localhost:18080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "vendor-react",
              test: /node_modules[\\/](react|react-dom|react-router|react-router-dom)[\\/]/,
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
              test: /node_modules[\\/](@tanstack|axios|date-fns|zustand)[\\/]/,
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
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": apiURL,
      "/openapi.json": apiURL,
    },
  },
});
