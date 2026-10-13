import { describe, expect, it } from 'vitest';
import { collect, detect } from '../src/collect.js';
import type { Fetcher } from '../src/model.js';

/** A fetcher serving a fixed set of URLs and recording what was asked of it. */
function server(routes: Record<string, string | number>) {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetcher: Fetcher = async (url, headers = {}) => {
    calls.push({ url, headers });
    const route = routes[url];
    if (typeof route === 'string') return { url, status: 200, headers: {}, body: route };
    return { url, status: route ?? 404, headers: {}, body: '' };
  };
  return { fetcher, calls };
}

const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const TOKEN = `${segment({ alg: 'ES256' })}.${segment({ iss: 'https://op.example' })}.c2lnbmF0dXJl`;

const METADATA =
  '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>';

describe('detect', () => {
  it('treats pasted XML as SAML without any request', async () => {
    const { fetcher, calls } = server({});
    expect(await detect(`\n ${METADATA}`, fetcher)).toBe('saml');
    expect(calls).toHaveLength(0);
  });

  it('recognises a metadata URL by what it serves', async () => {
    const { fetcher } = server({ 'https://idp.example/app/sso': METADATA });
    expect(await detect('https://idp.example/app/sso', fetcher)).toBe('saml');
  });

  it('recognises an issuer by its discovery document', async () => {
    const { fetcher } = server({ 'https://op.example/.well-known/openid-configuration': '{}' });
    expect(await detect('op.example', fetcher)).toBe('oidc');
  });

  it('recognises a SCIM base URL that demands authentication', async () => {
    const { fetcher } = server({ 'https://app.example/api/ServiceProviderConfig': 401 });
    expect(await detect('https://app.example/api', fetcher)).toBe('scim');
  });

  it('treats a pasted token as OIDC without any request', async () => {
    const { fetcher, calls } = server({});
    expect(await detect(TOKEN, fetcher)).toBe('oidc');
    expect(calls).toHaveLength(0);
  });

  it('falls back on the URL shape when the host is unreachable', async () => {
    const { fetcher } = server({ 'https://idp.example/saml/idp': 0 });
    expect(await detect('https://idp.example/saml/idp', fetcher)).toBe('saml');
  });
});

describe('collect', () => {
  it('follows jwks_uri from the discovery document', async () => {
    const { fetcher } = server({
      'https://op.example/.well-known/openid-configuration': JSON.stringify({
        jwks_uri: 'https://keys.example/jwks',
      }),
      'https://keys.example/jwks': '{"keys":[]}',
    });
    const workspace = await collect('https://op.example/.well-known/openid-configuration', fetcher);
    expect(workspace.target).toEqual({ protocol: 'oidc', input: 'https://op.example' });
    expect(workspace.evidence.map((e) => [e.kind, e.source])).toEqual([
      ['oidc.discovery', 'https://op.example/.well-known/openid-configuration'],
      ['oidc.jwks', 'https://keys.example/jwks'],
    ]);
  });

  it('asks the issuer a pasted token names for its documents, and sends the token nowhere', async () => {
    const { fetcher, calls } = server({
      'https://op.example/.well-known/openid-configuration': JSON.stringify({
        jwks_uri: 'https://op.example/jwks',
      }),
      'https://op.example/jwks': '{"keys":[]}',
    });
    const workspace = await collect(`  ${TOKEN}\n`, fetcher);
    expect(workspace.target).toEqual({ protocol: 'oidc', input: 'https://op.example' });
    expect(workspace.evidence.map((e) => [e.kind, e.provenance])).toEqual([
      ['oidc.id-token', 'user-supplied'],
      ['oidc.discovery', 'discovered'],
      ['oidc.jwks', 'discovered'],
    ]);
    expect(calls.map((c) => c.url)).toEqual([
      'https://op.example/.well-known/openid-configuration',
      'https://op.example/jwks',
    ]);
    expect(JSON.stringify(calls)).not.toContain(TOKEN.split('.')[2]);
  });

  it('requests nothing for a token that names no issuer', async () => {
    const { fetcher, calls } = server({});
    const workspace = await collect(
      `${segment({ alg: 'none' })}.${segment({ sub: 'x' })}.`,
      fetcher,
    );
    expect(workspace.target.input).toBe('pasted token');
    expect(calls).toHaveLength(0);
  });

  it('sends SCIM headers to SCIM endpoints and nowhere else', async () => {
    const { fetcher, calls } = server({});
    const scimHeaders = { authorization: 'Bearer secret' };
    await collect('https://app.example/scim/v2/', fetcher, { scimHeaders });
    expect(calls.map((c) => c.url)).toEqual([
      'https://app.example/scim/v2/ServiceProviderConfig',
      'https://app.example/scim/v2/ResourceTypes',
      'https://app.example/scim/v2/Schemas',
    ]);
    expect(calls.every((c) => c.headers.authorization === 'Bearer secret')).toBe(true);

    const other = server({});
    await collect('https://op.example', other.fetcher, { protocol: 'oidc', scimHeaders });
    expect(other.calls.some((c) => 'authorization' in c.headers)).toBe(false);
  });
});
