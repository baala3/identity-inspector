import { handle } from '@identity-inspector/proxy';
import react from '@vitejs/plugin-react';
import { type Connect, defineConfig, type Plugin } from 'vite';

/** Serves the proxy under /api so development needs no second process. */
function localProxy(): Plugin {
  const mount = ({ middlewares }: { middlewares: Connect.Server }) => {
    middlewares.use('/api', async (req, res) => {
      const response = await handle(
        new Request(`http://localhost${req.url}`, { method: req.method ?? 'GET' }),
        { allowPrivate: process.env.IDI_ALLOW_PRIVATE === '1' },
      );
      res.statusCode = response.status;
      for (const [name, value] of response.headers) res.setHeader(name, value);
      res.end(await response.text());
    });
  };
  return {
    name: 'identity-inspector-proxy',
    configureServer: mount,
    configurePreviewServer: mount,
  };
}

export default defineConfig({
  plugins: [react(), localProxy()],
  worker: { format: 'es' },
});
