import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["test/test.js"],
    setupFiles: ["test/vitest.setup.js"],
    pool: "forks",
    maxWorkers: 1,
    coverage: {
      include: ["index.js"],
      reporter: ["lcov", "text-summary", "html"],
    },
  },
});
