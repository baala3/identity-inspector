import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: 'list',
  use: { baseURL: 'http://localhost:5183' },
  webServer: {
    command: 'pnpm dev --port 5183 --strictPort',
    url: 'http://localhost:5183',
    // The local proxy must reach Keycloak on localhost, which the public-host guard refuses.
    env: { IDI_ALLOW_PRIVATE: '1' },
    reuseExistingServer: false,
  },
});
