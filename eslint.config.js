import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

const rules = {
  "no-alert": "warn",
  "no-eval": "error",
  "require-await": "warn",
  "no-useless-escape": "warn"
}

export default [
  {
    files: ["lib/**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.node
    },
    rules: {
      ...eslint.configs.recommended.rules,
      ...rules
    }
  },
  {
    files: ["types/**/*.d.ts"],
    plugins: { "@typescript-eslint": tseslint.plugin },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { project: "./tsconfig.json" },
    },
    rules: {
      ...eslint.configs.recommended.rules,
      ...Object.assign({}, ...tseslint.configs.recommended.map(config => config.rules ?? {}))
    }
  }
];