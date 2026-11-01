import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 90_000,
  workers: 1,
  use: {
    baseURL: process.env.PATCH8_TEST_URL || "http://localhost:8000",
    channel: "chrome",
    headless: true,
    screenshot: "only-on-failure",
  },
});
