import { defineConfig } from 'vitest/config';

// The tests were written for Jest in the main CookingOS repo. Vitest runs them unchanged with
// `globals: true`. Each test builds a throwaway git repo, so they get a generous timeout.
export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    testTimeout: 30000,
  },
});
