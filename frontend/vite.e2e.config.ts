import { defineConfig } from 'vite';
import { createAppConfig } from './vite.config.ts';

// Never proxy a missed test request to the deployed backend.
export default defineConfig((env) => {
  return createAppConfig(env, false);
});
