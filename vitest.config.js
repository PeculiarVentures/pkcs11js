const { defineConfig } = require("vitest/config");

module.exports = defineConfig({
  test: {
    globals: true,
    include: ["test/test.js"],
    setupFiles: ["test/vitest.setup.js"],
    pool: "forks",
    maxWorkers: 1,
  },
});
