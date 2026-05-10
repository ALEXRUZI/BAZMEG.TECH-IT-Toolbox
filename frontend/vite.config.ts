import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');

  const backendOrigin = env.BACKEND_ORIGIN || 'https://toolbox.bazmeg.tech';

  return {
    plugins: [react(), tailwindcss()],
    server: {
      proxy: {
        '/api': {
          target: backendOrigin,
          changeOrigin: true,
          secure: true,
        },
      },
    },
  };
});
