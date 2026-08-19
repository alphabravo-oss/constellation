// Minimal ESLint v9 flat config. We rely on tsc for type-checking and ESLint mostly for
// hook-rules + react-refresh hygiene. The TS plugin's typed rules require a parserOptions.project
// pointer which we deliberately omit (vitest+vite tsconfig juggling is more pain than it's worth
// at v1; tsc --noEmit catches type errors).
import js from "@eslint/js";
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
        document: "readonly",
        window: "readonly",
        navigator: "readonly",
        console: "readonly",
        fetch: "readonly",
        localStorage: "readonly",
        sessionStorage: "readonly",
        process: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        HTMLElement: "readonly",
        HTMLInputElement: "readonly",
        HTMLDivElement: "readonly",
        HTMLButtonElement: "readonly",
        HTMLTextAreaElement: "readonly",
        HTMLAnchorElement: "readonly",
        Event: "readonly",
        EventTarget: "readonly",
        MouseEvent: "readonly",
        KeyboardEvent: "readonly",
        CustomEvent: "readonly",
        crypto: "readonly",
        prompt: "readonly",
        confirm: "readonly",
        alert: "readonly",
        React: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        global: "readonly",
        Buffer: "readonly",
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
