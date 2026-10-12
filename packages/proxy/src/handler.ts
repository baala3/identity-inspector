import { dohResolver, type Resolver, refusal } from './guard.js';

export interface ProxyOptions {
  resolve?: Resolver;
  /** Origin allowed to call the proxy; defaults to any. */
  allowOrigin?: string;
  /** Skips the public-host guard. For local development against a local target only. */
  allowPrivate?: boolean;
}

const MAX_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 10_000;
// The response headers checks are allowed to judge.
const HEADERS = [
  'content-type',
  'cache-control',
  'www-authenticate',
  'access-control-allow-origin',
];

interface Fetched {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}

async function readCapped(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_BYTES) {
      await reader.cancel();
      throw new Error(`response exceeds ${MAX_BYTES} bytes`);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    all.set(chunk, at);
    at += chunk.length;
  }
  return new TextDecoder().decode(all);
}

/** Fetches one public document. The caller controls nothing but the URL. */
async function fetchPublic(target: string, options: ProxyOptions): Promise<Fetched> {
  const failed = (error: string): Fetched => ({
    url: target,
    status: 0,
    headers: {},
    body: '',
    error,
  });
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    return failed('not a URL');
  }
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (!options.allowPrivate) {
        const why = await refusal(url, options.resolve ?? dohResolver);
        if (why) return failed(`refused: ${why}`);
      }
      const response = await fetch(url, {
        redirect: 'manual',
        signal,
        headers: {
          accept:
            'application/json, application/scim+json, application/samlmetadata+xml, application/xml, */*;q=0.5',
          'user-agent': 'identity-inspector-proxy',
        },
      });
      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location) {
        // Every hop is judged again, so a public host cannot bounce us inward.
        url = new URL(location, url);
        continue;
      }
      const headers: Record<string, string> = {};
      for (const name of HEADERS) {
        const value = response.headers.get(name);
        if (value !== null) headers[name] = value;
      }
      return { url: target, status: response.status, headers, body: await readCapped(response) };
    }
    return failed('too many redirects');
  } catch (error) {
    return failed(error instanceof Error ? error.message : String(error));
  }
}

export async function handle(request: Request, options: ProxyOptions = {}): Promise<Response> {
  const cors = {
    'access-control-allow-origin': options.allowOrigin ?? '*',
    'access-control-allow-methods': 'GET',
    vary: 'origin',
  };
  const reply = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...cors, 'content-type': 'application/json', 'cache-control': 'no-store' },
    });

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const { pathname, searchParams } = new URL(request.url);
  if (request.method !== 'GET' || pathname !== '/fetch') return reply(404, { error: 'not found' });
  const target = searchParams.get('url');
  if (!target) return reply(400, { error: 'url is required' });
  return reply(200, await fetchPublic(target, options));
}
