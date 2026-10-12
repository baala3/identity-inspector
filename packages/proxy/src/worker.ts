import { handle } from './handler.js';

interface Env {
  ALLOW_ORIGIN?: string;
  RATE_LIMITER?: { limit(options: { key: string }): Promise<{ success: boolean }> };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const client = request.headers.get('cf-connecting-ip') ?? 'unknown';
    const allowed = await env.RATE_LIMITER?.limit({ key: client });
    if (allowed && !allowed.success) {
      return new Response(JSON.stringify({ error: 'rate limit exceeded' }), {
        status: 429,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': env.ALLOW_ORIGIN ?? '*',
        },
      });
    }
    return handle(request, env.ALLOW_ORIGIN ? { allowOrigin: env.ALLOW_ORIGIN } : {});
  },
};
