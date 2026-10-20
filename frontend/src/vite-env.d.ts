/// <reference types="vite/client" />

// Build-time constants from vite.config.ts `define`. Read them through src/lib/build-info.ts,
// which also tolerates their absence under vitest.
declare const __APP_VERSION__: string;
declare const __APP_COMMIT__: string;
declare const __APP_BUILD_DATE__: string;
