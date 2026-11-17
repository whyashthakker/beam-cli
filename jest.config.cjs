/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  watchman: false,
  roots: ["<rootDir>/tests"],
  // tests/audit/*.test.ts use node's built-in test runner (node:test), not Jest globals -- run
  // separately via `npm run test:audit` (chained into `npm test`), not picked up here.
  testPathIgnorePatterns: ["<rootDir>/node_modules/", "<rootDir>/tests/audit/"],
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1"
  },
  transform: {
    "^.+\\.tsx?$": ["ts-jest", {
      useESM: true,
      tsconfig: "<rootDir>/tsconfig.json",
      diagnostics: true
    }]
  },
  collectCoverageFrom: [
    "src/**/*.ts",
    "!src/cli.ts"
  ],
  clearMocks: true,
  restoreMocks: true
};
