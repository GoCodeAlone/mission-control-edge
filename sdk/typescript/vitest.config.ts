import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    maxWorkers: 1,
    sequence: { concurrent: false },
    testTimeout: 30_000,
  },
});
