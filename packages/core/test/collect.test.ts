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

const RESPONSE = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"><saml:Issuer>https://idp.example/metadata</saml:Issuer></samlp:Response>`;

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

  it('recognises an authorization server by its metadata, before trying SCIM', async () => {
    const { fetcher, calls } = server({
      'https://as.example/.well-known/oauth-authorization-server': '{}',
    });
    expect(await detect('as.example', fetcher)).toBe('oauth');
    expect(calls.some((c) => c.url.endsWith('/ServiceProviderConfig'))).toBe(false);
  });

  it('recognises the URL of authorization server metadata without any request', async () => {
    const { fetcher, calls } = server({});
    const url = 'https://as.example/.well-known/oauth-authorization-server/tenant';
    expect(await detect(url, fetcher)).toBe('oauth');
    expect(calls).toHaveLength(0);
  });

  it('takes a target that publishes both documents for an OpenID Provider', async () => {
    const { fetcher } = server({
      'https://op.example/.well-known/openid-configuration': '{}',
      'https://op.example/.well-known/oauth-authorization-server': '{}',
    });
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

  it('does not mistake a three-part hostname for a token', async () => {
    const { fetcher, calls } = server({
      'https://accounts.example.com/.well-known/openid-configuration': '{}',
    });
    expect(await detect('accounts.example.com', fetcher)).toBe('oidc');
    const workspace = await collect('accounts.example.com', fetcher);
    expect(workspace.target.input).toBe('https://accounts.example.com');
    expect(workspace.evidence.map((e) => e.kind)).toEqual(['oidc.discovery']);
    expect(calls.length).toBeGreaterThan(0);
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

  it('reads an authorization server from its metadata, and asks whether it has an OpenID configuration', async () => {
    const { fetcher, calls } = server({
      // RFC 8414 puts the well-known segment ahead of the issuer path, not after it.
      'https://as.example/.well-known/oauth-authorization-server/tenant': JSON.stringify({
        issuer: 'https://as.example/tenant',
        jwks_uri: 'https://as.example/tenant/jwks',
      }),
      'https://as.example/tenant/jwks': '{"keys":[]}',
    });
    for (const input of [
      'https://as.example/tenant/',
      'https://as.example/.well-known/oauth-authorization-server/tenant',
    ]) {
      calls.length = 0;
      const workspace = await collect(input, fetcher);
      expect(workspace.target).toEqual({
        protocol: 'oauth',
        input: input.replace(/\/\.well-known\/[^/]+/, ''),
      });
      expect(workspace.evidence.map((e) => [e.kind, e.fetch?.status])).toEqual([
        ['oauth.metadata', 200],
        ['oidc.discovery', 404],
        ['oidc.jwks', 200],
      ]);
      expect(calls.slice(-3).map((c) => c.url)).toEqual([
        'https://as.example/.well-known/oauth-authorization-server/tenant',
        'https://as.example/tenant/.well-known/openid-configuration',
        'https://as.example/tenant/jwks',
      ]);
    }
  });

  it('does not look for authorization server metadata when told the target is an OpenID Provider', async () => {
    const { fetcher, calls } = server({
      'https://as.example/.well-known/oauth-authorization-server': '{}',
    });
    const workspace = await collect('as.example', fetcher, { protocol: 'oidc' });
    expect(workspace.target.protocol).toBe('oidc');
    expect(workspace.evidence.map((e) => [e.kind, e.fetch?.status])).toEqual([
      ['oidc.discovery', 404],
    ]);
    expect(calls).toHaveLength(1);
  });

  it('checks a pasted token against a plain authorization server when its issuer is one', async () => {
    const { fetcher, calls } = server({
      'https://op.example/.well-known/oauth-authorization-server': JSON.stringify({
        jwks_uri: 'https://op.example/jwks',
      }),
      'https://op.example/jwks': '{"keys":[]}',
    });
    const workspace = await collect(TOKEN, fetcher);
    expect(workspace.target).toEqual({ protocol: 'oauth', input: 'https://op.example' });
    expect(workspace.evidence.map((e) => e.kind)).toEqual([
      'oidc.token',
      'oauth.metadata',
      'oidc.discovery',
      'oidc.jwks',
    ]);
    expect(JSON.stringify(calls)).not.toContain(TOKEN.split('.')[2]);

    // An issuer that publishes neither document is still reported as the provider it claims to be.
    const neither = await collect(TOKEN, server({}).fetcher);
    expect(neither.target.protocol).toBe('oidc');
    expect(neither.evidence.map((e) => e.kind)).toEqual(['oidc.token', 'oidc.discovery']);
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
      ['oidc.token', 'user-supplied'],
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

  it('reads a SAML response pasted as the base64 the browser posted, and requests nothing', async () => {
    const { fetcher, calls } = server({});
    const posted = encodeURIComponent(Buffer.from(RESPONSE).toString('base64'));
    expect(await detect(posted, fetcher)).toBe('saml');
    const workspace = await collect(posted, fetcher);
    expect(workspace.target).toEqual({ protocol: 'saml', input: 'https://idp.example/metadata' });
    expect(workspace.evidence).toEqual([
      { id: 'saml.response', kind: 'saml.response', provenance: 'user-supplied', raw: RESPONSE },
    ]);
    expect(calls).toHaveLength(0);
  });

  it('recognises a response behind a declaration or a DTD, and leaves metadata alone', async () => {
    const { fetcher } = server({});
    const behind = `<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY e "x">]>\n${RESPONSE}`;
    expect((await collect(behind, fetcher)).evidence[0]?.kind).toBe('saml.response');
    expect((await collect(METADATA, fetcher)).evidence[0]?.kind).toBe('saml.metadata');
  });

  it('fetches IdP metadata for a pasted response only from the URL given for it', async () => {
    const { fetcher, calls } = server({ 'https://idp.example/metadata': METADATA });
    const workspace = await collect(RESPONSE, fetcher, {
      samlMetadata: 'https://idp.example/metadata',
    });
    expect(workspace.evidence.map((e) => [e.kind, e.provenance])).toEqual([
      ['saml.response', 'user-supplied'],
      ['saml.metadata', 'discovered'],
    ]);
    expect(calls.map((c) => c.url)).toEqual(['https://idp.example/metadata']);

    const pasted = await collect(RESPONSE, server({}).fetcher, { samlMetadata: METADATA });
    expect(pasted.evidence[1]).toMatchObject({
      kind: 'saml.metadata',
      provenance: 'user-supplied',
    });
  });

  it.each([
    ['a token', TOKEN, 'scim'],
    ['a token', TOKEN, 'oauth'],
    ['a token', TOKEN, 'saml'],
    ['metadata', METADATA, 'oidc'],
    ['metadata', METADATA, 'oauth'],
    ['metadata', METADATA, 'scim'],
    ['a response', RESPONSE, 'oidc'],
    ['a response', Buffer.from(RESPONSE).toString('base64'), 'scim'],
  ] as const)(
    'refuses %s pasted under a protocol that cannot read it, and requests nothing',
    async (_, pasted, protocol) => {
      const { fetcher, calls } = server({});
      await expect(collect(pasted, fetcher, { protocol })).rejects.toThrow(/was not sent anywhere/);
      expect(calls).toHaveLength(0);
    },
  );

  it('refuses a token given where the metadata of a response belongs', async () => {
    const { fetcher, calls } = server({});
    await expect(collect(RESPONSE, fetcher, { samlMetadata: TOKEN })).rejects.toThrow(
      /was not sent anywhere/,
    );
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
