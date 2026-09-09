/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  watchman: false,
  roots: ["<rootDir>/tests"],
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
