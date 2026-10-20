// Minimal ESLint flat config. We rely on tsc for type-checking and ESLint mostly for
// hook-rules + react-refresh hygiene. The TS plugin's typed rules require a parserOptions.project
// pointer which we deliberately omit (vitest+vite tsconfig juggling is more pain than it's worth
// at v1; tsc --noEmit catches type errors).
//
// Globals come from the `globals` package: the previous hand-written list drifted behind the DOM
// surface the app actually uses (17 no-undef errors), and js.configs.recommended keeps no-undef on
// even for TS files.
import js from "@eslint/js";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";

export default [
  {
    ignores: ["dist/**", "node_modules/**", "playwright-report/**", "test-results/**", "e2e/**"],
  },
  js.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.es2024,
        React: "readonly",
        // Type-only fetch global that the `globals` package does not list.
        RequestInit: "readonly",
        // Build-time constants stamped by vite.config.ts `define`.
        __APP_VERSION__: "readonly",
        __APP_COMMIT__: "readonly",
        __APP_BUILD_DATE__: "readonly",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "no-empty": ["error", { allowEmptyCatch: true }],
      "no-unused-vars": "off",
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
];
