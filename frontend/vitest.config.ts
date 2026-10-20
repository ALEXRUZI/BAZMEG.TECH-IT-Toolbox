import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  test: {
    include: ['tests/**/*.test.{ts,tsx,mjs}'],
    environment: 'jsdom',
    setupFiles: ['tests/setup.ts'],
    clearMocks: true,
  },
});
