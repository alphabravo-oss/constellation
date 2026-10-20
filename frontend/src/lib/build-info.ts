// Build metadata stamped by vite.config.ts `define`. vitest does not define them, hence the
// typeof guards instead of bare references.
export const BUILD_INFO = {
  version: typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "dev",
  commit: typeof __APP_COMMIT__ !== "undefined" ? __APP_COMMIT__ : "",
  buildDate: typeof __APP_BUILD_DATE__ !== "undefined" ? __APP_BUILD_DATE__ : "",
} as const;
