/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_RAXIS_DASHBOARD_AUTH_BYPASS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
