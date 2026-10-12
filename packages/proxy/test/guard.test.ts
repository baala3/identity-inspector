import { afterEach, describe, expect, it, vi } from 'vitest';
import { isPublicAddress, refusal } from '../src/guard.js';
import { handle } from '../src/handler.js';

const resolveTo =
  (...addresses: string[]) =>
  async () =>
    addresses;

describe('isPublicAddress', () => {
  it.each([
    '10.0.0.1',
    '127.0.0.1',
    '169.254.169.254',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '100.64.0.1',
    '0.0.0.0',
    '224.0.0.1',
    '198.18.0.1',
    '::1',
    '::',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'ff02::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '64:ff9b::10.0.0.1',
    'not-an-ip',
  ])('rejects %s', (address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it.each(['8.8.8.8', '172.32.0.1', '100.128.0.1', '2606:4700::1111', '::ffff:8.8.8.8'])(
    'accepts %s',
    (address) => {
      expect(isPublicAddress(address)).toBe(true);
    },
  );
});

describe('refusal', () => {
  const check = (url: string, ...addresses: string[]) =>
    refusal(new URL(url), resolveTo(...addresses));

  it('allows a public host', async () => {
    expect(await check('https://idp.example.com/metadata', '93.184.216.34')).toBeUndefined();
  });

  it.each([
    ['ftp://idp.example.com/x', /only http/],
    ['https://user:pw@idp.example.com/', /credentials/],
    ['https://idp.example.com:6379/', /port/],
    ['http://127.0.0.1/', /not public/],
    ['http://[::1]/', /not public/],
    ['http://2130706433/', /not public/],
    ['http://localhost/', /not public/],
    ['https://db.internal/', /not public/],
    ['https://intranet/', /not public/],
  ])('refuses %s', async (url, why) => {
    expect(await check(url, '93.184.216.34')).toMatch(why);
  });

  it('refuses a public name that resolves inward', async () => {
    expect(await check('https://rebind.example.com/', '93.184.216.34', '10.0.0.5')).toMatch(
      /resolves to a non-public/,
    );
  });

  it('refuses a name that does not resolve', async () => {
    expect(await check('https://nowhere.example.com/')).toMatch(/does not resolve/);
  });
});

describe('handle', () => {
  afterEach(() => vi.unstubAllGlobals());

  const get = (target: string, resolve = resolveTo('93.184.216.34')) =>
    handle(new Request(`https://proxy.example/fetch?url=${encodeURIComponent(target)}`), {
      resolve,
    }).then(
      (r) =>
        r.json() as Promise<{
          status: number;
          body: string;
          error?: string;
          headers: Record<string, string>;
        }>,
    );

  it('returns the document and only the allowed headers', async () => {
    const upstream = vi.fn(
      async (_url: URL, _init: RequestInit) =>
        new Response('{"issuer":"x"}', {
          headers: { 'content-type': 'application/json', 'set-cookie': 'a=b' },
        }),
    );
    vi.stubGlobal('fetch', upstream);
    const result = await get('https://op.example.com/.well-known/openid-configuration');
    expect(result).toMatchObject({
      status: 200,
      body: '{"issuer":"x"}',
      headers: { 'content-type': 'application/json' },
    });
    expect(result.headers).not.toHaveProperty('set-cookie');
  });

  it('never forwards the caller headers upstream', async () => {
    const upstream = vi.fn(async (_url: URL, _init: RequestInit) => new Response('{}'));
    vi.stubGlobal('fetch', upstream);
    await handle(
      new Request(
        'https://proxy.example/fetch?url=https%3A%2F%2Fapp.example.com%2Fscim%2Fv2%2FSchemas',
        {
          headers: { authorization: 'Bearer secret', cookie: 'session=1' },
        },
      ),
      { resolve: resolveTo('93.184.216.34') },
    );
    const sent = new Headers(upstream.mock.calls[0]?.[1].headers);
    expect([sent.get('authorization'), sent.get('cookie')]).toEqual([null, null]);
  });

  it('re-checks the destination of a redirect', async () => {
    const upstream = vi.fn(
      async (_url: URL, _init: RequestInit) =>
        new Response(null, {
          status: 302,
          headers: { location: 'http://169.254.169.254/latest/meta-data/' },
        }),
    );
    vi.stubGlobal('fetch', upstream);
    const result = await get('https://op.example.com/redirect');
    expect(result).toMatchObject({ status: 0, error: 'refused: the address is not public' });
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it('refuses an oversized body', async () => {
    vi.stubGlobal('fetch', async () => new Response('x'.repeat(2 * 1024 * 1024 + 1)));
    expect((await get('https://op.example.com/big')).error).toMatch(/exceeds/);
  });

  it('rejects anything but GET /fetch', async () => {
    const response = await handle(
      new Request('https://proxy.example/fetch?url=https://a.example.com', { method: 'POST' }),
    );
    expect(response.status).toBe(404);
  });
});
