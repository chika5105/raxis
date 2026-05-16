/// <reference types="vitest" />
import path from "node:path";
import { defineConfig, type UserConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite config for the Raxis operator dashboard.
//
// Production build emits a static bundle into `dist/` which the
// Rust dashboard server (raxis-dashboard) serves via
// `static_dir`.
//
// In dev, requests to `/api/*` and `/sse/*` are proxied to the
// kernel-hosted dashboard on `127.0.0.1:9820` (the spec default).
// Override with VITE_DASHBOARD_PROXY_TARGET if your kernel
// listens elsewhere.
const proxyTarget =
  process.env.VITE_DASHBOARD_PROXY_TARGET ?? "http://127.0.0.1:9820";

export default defineConfig(({ command }): UserConfig => ({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy:
      command === "serve"
        ? {
            "/api": {
              target: proxyTarget,
              changeOrigin: true,
              ws: false,
            },
          }
        : undefined,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    target: "es2022",
    rollupOptions: {
      output: {
        // Stable chunk names so the Rust ServeDir + the
        // dashboard server's compression middleware cache
        // entries don't churn on every build.
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          query: ["@tanstack/react-query"],
          monaco: ["@monaco-editor/react"],
          dagre: ["dagre"],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
}));
