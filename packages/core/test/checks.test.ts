import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { checks, evaluate } from '../src/engine.js';
import type { Evidence, EvidenceKind, Severity, Workspace } from '../src/model.js';

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8').trim();
const CERT = fixture('rsa2048.b64');
const WEAK_CERT = fixture('rsa1024.b64');
// Both fixture certificates are valid from 2025-01-01 to 2030-01-01.
const NOW = new Date('2027-06-01T00:00:00Z');

type Doc = Record<string, unknown>;

function fetched(
  kind: EvidenceKind,
  body: unknown,
  status = 200,
  type = 'application/json',
): Evidence {
  return {
    id: kind,
    kind,
    provenance: 'discovered',
    source: `https://target.example/${kind}`,
    fetch: { status, headers: { 'content-type': type } },
    raw: typeof body === 'string' ? body : JSON.stringify(body),
  };
}

// --- OIDC ---------------------------------------------------------------

const modulus = (bytes: number) =>
  Buffer.concat([Buffer.from([0xc3]), Buffer.alloc(bytes - 1, 7)]).toString('base64url');

const DISCOVERY: Doc = {
  issuer: 'https://op.example',
  authorization_endpoint: 'https://op.example/authorize',
  token_endpoint: 'https://op.example/token',
  userinfo_endpoint: 'https://op.example/userinfo',
  jwks_uri: 'https://op.example/jwks',
  response_types_supported: ['code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  scopes_supported: ['openid', 'email'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256'],
  authorization_response_iss_parameter_supported: true,
};

const KEYS: Doc[] = [
  { kty: 'RSA', kid: 'a', use: 'sig', e: 'AQAB', n: modulus(256), x5c: [CERT] },
  { kty: 'RSA', kid: 'b', use: 'sig', e: 'AQAB', n: modulus(256) },
];

interface OidcOptions {
  discovery?: Doc;
  keys?: Doc[];
  input?: string;
  discoveryStatus?: number;
  discoveryType?: string;
  jwksStatus?: number;
}

function oidc(o: OidcOptions = {}): Workspace {
  return {
    target: { protocol: 'oidc', input: o.input ?? 'https://op.example' },
    evidence: [
      fetched(
        'oidc.discovery',
        { ...DISCOVERY, ...o.discovery },
        o.discoveryStatus,
        o.discoveryType,
      ),
      fetched('oidc.jwks', { keys: o.keys ?? KEYS }, o.jwksStatus),
    ],
  };
}

const without = (doc: Doc, key: string) =>
  Object.fromEntries(Object.entries(doc).filter(([k]) => k !== key));
const lacking = (key: string): Workspace => {
  const ws = oidc();
  ws.evidence[0] = fetched('oidc.discovery', without(DISCOVERY, key));
  return ws;
};

// --- SAML ---------------------------------------------------------------

interface SamlOptions {
  entityAttrs?: string;
  idpAttrs?: string;
  keys?: string;
  sso?: string;
  nameId?: string;
  signature?: string;
  role?: 'idp' | 'sp' | 'none';
  spAttrs?: string;
  acs?: string;
}

const key = (cert: string, use = 'use="signing"') =>
  `<md:KeyDescriptor ${use}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;

const PROTOCOLS = 'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"';
const POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

function samlXml(o: SamlOptions = {}): string {
  const role = o.role ?? 'idp';
  const idp = `<md:IDPSSODescriptor ${o.idpAttrs ?? PROTOCOLS}>${o.keys ?? key(CERT)}${
    o.nameId ??
    '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
  }${o.sso ?? `<md:SingleSignOnService Binding="${REDIRECT}" Location="https://idp.example/sso"/>`}</md:IDPSSODescriptor>`;
  const sp = `<md:SPSSODescriptor ${o.spAttrs ?? `${PROTOCOLS} WantAssertionsSigned="true"`}>${
    o.acs ??
    `<md:AssertionConsumerService Binding="${POST}" Location="https://sp.example/acs" index="0"/>`
  }</md:SPSSODescriptor>`;
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ${
    o.entityAttrs ?? 'entityID="https://idp.example/metadata" validUntil="2029-01-01T00:00:00Z"'
  }>${o.signature ?? ''}${role === 'idp' ? idp : role === 'sp' ? sp : ''}</md:EntityDescriptor>`;
}

const pasted = (raw: string): Workspace => ({
  target: { protocol: 'saml', input: 'pasted metadata' },
  evidence: [{ id: 'saml.metadata', kind: 'saml.metadata', provenance: 'user-supplied', raw }],
});
const saml = (o: SamlOptions = {}) => pasted(samlXml(o));
const samlFetched = (status: number): Workspace => ({
  target: { protocol: 'saml', input: 'https://idp.example/metadata' },
  evidence: [fetched('saml.metadata', samlXml(), status, 'application/xml')],
});

// --- SCIM ---------------------------------------------------------------

const CORE = 'urn:ietf:params:scim:schemas:core:2.0:';
const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const SCIM_ERROR = { schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401' };

const CONFIG: Doc = {
  schemas: [`${CORE}ServiceProviderConfig`],
  patch: { supported: true },
  bulk: { supported: false },
  filter: { supported: true, maxResults: 200 },
  changePassword: { supported: false },
  sort: { supported: false },
  etag: { supported: false },
  authenticationSchemes: [{ type: 'oauthbearertoken', name: 'OAuth Bearer Token' }],
};
const TYPES: Doc[] = [
  {
    name: 'User',
    endpoint: '/Users',
    schema: `${CORE}User`,
    schemaExtensions: [{ schema: ENTERPRISE, required: false }],
  },
  { name: 'Group', endpoint: '/Groups', schema: `${CORE}Group` },
];
const USER_SCHEMA: Doc = {
  id: `${CORE}User`,
  attributes: [{ name: 'userName', required: true, uniqueness: 'server' }],
};
const SCHEMAS: Doc[] = [
  USER_SCHEMA,
  { id: `${CORE}Group`, attributes: [] },
  { id: ENTERPRISE, attributes: [] },
];

interface ScimOptions {
  config?: Doc;
  types?: Doc[];
  schemas?: Doc[];
  status?: number;
  type?: string;
  errorBody?: unknown;
  input?: string;
}

function scim(o: ScimOptions = {}): Workspace {
  const type = o.type ?? 'application/scim+json';
  const list = (Resources: Doc[]) => ({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
    Resources,
  });
  const body = (ok: unknown) => (o.status && o.status !== 200 ? (o.errorBody ?? SCIM_ERROR) : ok);
  return {
    target: { protocol: 'scim', input: o.input ?? 'https://app.example/scim/v2' },
    evidence: [
      fetched('scim.service-provider-config', body({ ...CONFIG, ...o.config }), o.status, type),
      fetched('scim.resource-types', body(list(o.types ?? TYPES)), o.status, type),
      fetched('scim.schemas', body(list(o.schemas ?? SCHEMAS)), o.status, type),
    ],
  };
}

// --- Scenarios ----------------------------------------------------------

/** [workspace, expected severity, expected detail, evaluation instant] */
type Scenario = [Workspace, Severity, RegExp?, Date?];

// Per ADR 0003, every check needs at least two scenarios with different verdicts.
const scenarios: Record<string, Scenario[]> = {
  'oidc.discovery.reachable': [
    [oidc(), 'pass'],
    [oidc({ discoveryStatus: 404 }), 'error', /HTTP 404/],
  ],
  'oidc.discovery.content-type': [
    [oidc(), 'pass'],
    [oidc({ discoveryType: 'text/html' }), 'warn'],
  ],
  'oidc.discovery.issuer-match': [
    [oidc(), 'pass'],
    [oidc({ input: 'https://op.example/' }), 'info', /trailing slash/],
    [oidc({ input: 'https://other.example' }), 'error'],
  ],
  'oidc.discovery.issuer-templated': [
    [oidc(), 'pass'],
    [oidc({ discovery: { issuer: 'https://login.example/{tenantid}/v2.0' } }), 'warn'],
  ],
  'oidc.discovery.issuer-form': [
    [oidc(), 'pass'],
    [
      oidc({ discovery: { issuer: 'http://op.example?x=1' } }),
      'error',
      /scheme is http, it has a query/,
    ],
  ],
  'oidc.discovery.required-metadata': [
    [oidc(), 'pass'],
    [lacking('subject_types_supported'), 'error', /subject_types_supported/],
  ],
  'oidc.discovery.endpoints-https': [
    [oidc(), 'pass'],
    [oidc({ discovery: { token_endpoint: 'http://op.example/token' } }), 'error'],
  ],
  'oidc.discovery.endpoint-origins': [
    [oidc(), 'pass'],
    [oidc({ discovery: { token_endpoint: 'https://api.example/token' } }), 'info'],
  ],
  'oidc.discovery.code-flow': [
    [oidc(), 'pass'],
    [oidc({ discovery: { response_types_supported: ['id_token'] } }), 'error'],
  ],
  'oidc.discovery.implicit-advertised': [
    [oidc(), 'pass'],
    [oidc({ discovery: { response_types_supported: ['code', 'id_token token'] } }), 'warn'],
  ],
  'oidc.discovery.password-grant': [
    [oidc(), 'pass'],
    [oidc({ discovery: { grant_types_supported: ['password'] } }), 'warn'],
  ],
  'oidc.discovery.pkce-s256': [
    [oidc(), 'pass'],
    [lacking('code_challenge_methods_supported'), 'warn', /not proof/],
    [oidc({ discovery: { code_challenge_methods_supported: ['plain'] } }), 'error'],
    [oidc({ discovery: { code_challenge_methods_supported: ['plain', 'S256'] } }), 'info'],
  ],
  'oidc.discovery.rs256': [
    [oidc(), 'pass'],
    [oidc({ discovery: { id_token_signing_alg_values_supported: ['ES256'] } }), 'warn'],
  ],
  'oidc.discovery.alg-none': [
    [oidc(), 'pass'],
    [oidc({ discovery: { id_token_signing_alg_values_supported: ['RS256', 'none'] } }), 'warn'],
  ],
  'oidc.discovery.openid-scope': [
    [oidc(), 'pass'],
    [oidc({ discovery: { scopes_supported: ['email'] } }), 'warn'],
  ],
  'oidc.discovery.iss-parameter': [
    [oidc(), 'pass'],
    [lacking('authorization_response_iss_parameter_supported'), 'info'],
  ],
  'oidc.jwks.reachable': [
    [oidc(), 'pass'],
    [oidc({ jwksStatus: 500 }), 'error'],
  ],
  'oidc.jwks.signing-keys': [
    [oidc(), 'pass'],
    [oidc({ keys: [{ kty: 'RSA', kid: 'e', use: 'enc', n: modulus(256) }] }), 'error'],
  ],
  'oidc.jwks.private-material': [
    [oidc(), 'pass'],
    [oidc({ keys: [{ ...KEYS[0], d: 'AAAA' }] }), 'error'],
  ],
  'oidc.jwks.kid-missing': [
    [oidc(), 'pass'],
    [oidc({ keys: [KEYS[0] as Doc, without(KEYS[1] as Doc, 'kid')] }), 'warn'],
  ],
  'oidc.jwks.kid-duplicate': [
    [oidc(), 'pass'],
    [oidc({ keys: [KEYS[0] as Doc, { ...KEYS[1], kid: 'a' }] }), 'error'],
  ],
  'oidc.jwks.rsa-key-size': [
    [oidc(), 'pass', /2048, 2048/],
    [oidc({ keys: [{ kty: 'RSA', kid: 'w', n: modulus(128) }] }), 'error', /1024 bits/],
  ],
  'oidc.jwks.alg-coverage': [
    [oidc(), 'pass'],
    [
      oidc({ discovery: { id_token_signing_alg_values_supported: ['RS256', 'ES256'] } }),
      'warn',
      /ES256/,
    ],
  ],
  'oidc.jwks.x5c-validity': [
    [oidc(), 'pass'],
    [oidc(), 'warn', /expired/, new Date('2031-01-01T00:00:00Z')],
  ],

  'saml.metadata.reachable': [
    [samlFetched(200), 'pass'],
    [samlFetched(503), 'error'],
  ],
  'saml.metadata.well-formed': [
    [saml(), 'pass'],
    [pasted('<md:EntityDescriptor'), 'error', /Not parseable/],
    [pasted('<!DOCTYPE x [<!ENTITY a "b">]><x/>'), 'error', /DTD/],
    [pasted('<html xmlns="http://www.w3.org/1999/xhtml"/>'), 'error', /Root element/],
  ],
  'saml.metadata.entity-id': [
    [saml(), 'pass'],
    [saml({ entityAttrs: '' }), 'error'],
    [saml({ entityAttrs: 'entityID="https://sts.example/{tenantid}/"' }), 'warn', /template/],
  ],
  'saml.metadata.sso-role': [
    [saml(), 'pass'],
    [saml({ role: 'none' }), 'error'],
  ],
  'saml.metadata.protocol-support': [
    [saml(), 'pass'],
    [
      saml({ idpAttrs: 'protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"' }),
      'error',
    ],
  ],
  'saml.metadata.valid-until': [
    [saml(), 'pass'],
    [saml(), 'error', /expired/, new Date('2029-06-01T00:00:00Z')],
  ],
  'saml.metadata.signed': [
    [saml(), 'info', /unsigned/],
    [saml({ signature: '<ds:Signature/>' }), 'info', /not been verified/],
  ],
  'saml.metadata.endpoints-https': [
    [saml(), 'pass'],
    [
      saml({
        sso: `<md:SingleSignOnService Binding="${REDIRECT}" Location="http://idp.example/sso"/>`,
      }),
      'error',
    ],
  ],
  'saml.idp.sso-service': [
    [saml(), 'pass'],
    [saml({ sso: '' }), 'error'],
    [
      saml({
        sso: '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example/soap"/>',
      }),
      'warn',
    ],
  ],
  'saml.idp.signing-key': [
    [saml(), 'pass'],
    [saml({ keys: key(CERT, 'use="encryption"') }), 'error'],
  ],
  'saml.idp.signing-key-rollover': [
    [saml(), 'info', /One signing certificate/],
    [saml({ keys: key(CERT) + key(WEAK_CERT, '') }), 'info', /2 signing certificates/],
  ],
  'saml.idp.want-authn-requests-signed': [
    [saml(), 'info', /are accepted/],
    [saml({ idpAttrs: `${PROTOCOLS} WantAuthnRequestsSigned="true"` }), 'info', /will be rejected/],
  ],
  'saml.sp.acs': [
    [saml({ role: 'sp' }), 'pass'],
    [saml({ role: 'sp', acs: '' }), 'error', /no AssertionConsumerService/],
    [
      saml({
        role: 'sp',
        acs: `<md:AssertionConsumerService Binding="${REDIRECT}" Location="https://sp.example/a" index="1"/><md:AssertionConsumerService Binding="${REDIRECT}" Location="https://sp.example/b" index="1"/>`,
      }),
      'error',
      /not unique; no endpoint uses HTTP-POST/,
    ],
  ],
  'saml.sp.want-assertions-signed': [
    [saml({ role: 'sp' }), 'pass'],
    [saml({ role: 'sp', spAttrs: PROTOCOLS }), 'warn'],
  ],
  'saml.cert.readable': [
    [saml(), 'pass'],
    [saml({ keys: key('bm90IGEgY2VydA==') }), 'error'],
  ],
  'saml.cert.validity': [
    [saml(), 'pass'],
    [saml(), 'error', /expired/, new Date('2030-02-01T00:00:00Z')],
    [saml(), 'error', /not valid until/, new Date('2024-06-01T00:00:00Z')],
    [saml(), 'warn', /expires in 10 day/, new Date('2029-12-22T00:00:00Z')],
  ],
  'saml.cert.key-strength': [
    [saml(), 'pass'],
    [saml({ keys: key(WEAK_CERT) }), 'error', /1024 bits/],
  ],
  'saml.metadata.nameid-formats': [
    [saml(), 'info', /emailAddress/],
    [saml({ nameId: '' }), 'info', /No NameIDFormat/],
  ],

  'scim.base.https': [
    [scim(), 'pass'],
    [scim({ input: 'http://app.example/scim/v2' }), 'error'],
  ],
  'scim.discovery.reachable': [
    [scim(), 'pass'],
    [scim({ status: 401 }), 'info', /requires authentication/],
    [scim({ status: 404 }), 'error'],
  ],
  'scim.discovery.content-type': [
    [scim(), 'pass'],
    [scim({ type: 'application/json' }), 'warn'],
  ],
  'scim.error.shape': [
    [scim({ status: 401 }), 'pass'],
    [scim({ status: 401, errorBody: 'Unauthorized' }), 'warn'],
  ],
  'scim.config.schema': [
    [scim(), 'pass'],
    [scim({ config: { schemas: [], etag: undefined } }), 'error', /URN; missing etag/],
  ],
  'scim.config.patch': [
    [scim(), 'pass'],
    [scim({ config: { patch: { supported: false } } }), 'error'],
  ],
  'scim.config.filter': [
    [scim(), 'pass', /maxResults 200/],
    [scim({ config: { filter: { supported: false } } }), 'error'],
  ],
  'scim.config.auth-schemes': [
    [scim(), 'pass'],
    [scim({ config: { authenticationSchemes: [] } }), 'warn'],
  ],
  'scim.config.features': [
    [scim(), 'info', /bulk no/],
    [scim({ config: { bulk: { supported: true } } }), 'info', /bulk yes/],
  ],
  'scim.resource-types.user': [
    [scim(), 'pass', /Group resource type: present/],
    [scim({ types: [TYPES[1] as Doc] }), 'error'],
  ],
  'scim.schemas.referenced': [
    [scim(), 'pass'],
    [scim({ schemas: [USER_SCHEMA] }), 'warn', /Group/],
  ],
  'scim.schemas.user-name': [
    [scim(), 'pass'],
    [
      scim({
        schemas: [{ id: `${CORE}User`, attributes: [{ name: 'userName', required: false }] }],
      }),
      'warn',
    ],
  ],
  'scim.schemas.enterprise-extension': [
    [scim(), 'info', /is published/],
    [scim({ schemas: [USER_SCHEMA] }), 'info', /not published/],
  ],
};

describe('check catalog', () => {
  it('has unique identifiers', () => {
    const ids = checks.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('has scenarios for every check and no scenarios for unknown checks', () => {
    expect(Object.keys(scenarios).sort()).toEqual(checks.map((c) => c.id).sort());
  });

  for (const check of checks) {
    describe(check.id, () => {
      const cases = scenarios[check.id] ?? [];

      it('is exercised by at least two distinguishable scenarios', () => {
        const verdicts = new Set(cases.map(([, severity, detail]) => `${severity} ${detail}`));
        expect(verdicts.size).toBeGreaterThanOrEqual(2);
      });

      cases.forEach(([workspace, severity, detail, instant], index) => {
        it(`scenario ${index + 1} yields ${severity}${detail ? ` matching ${detail}` : ''}`, () => {
          const found = evaluate(workspace, instant ?? NOW).findings.filter(
            (f) => f.checkId === check.id,
          );
          expect(found.map((f) => f.severity)).toContain(severity);
          if (detail) expect(found.map((f) => f.detail).join('\n')).toMatch(detail);
        });
      });
    });
  }
});

describe('clean fixtures', () => {
  it.each([
    ['oidc', oidc()],
    ['saml idp', saml()],
    ['saml sp', saml({ role: 'sp' })],
    ['scim', scim()],
  ])('%s raises no errors or warnings', (_name, workspace) => {
    const { summary } = evaluate(workspace, NOW);
    expect([summary.error, summary.warn]).toEqual([0, 0]);
  });
});

describe('report', () => {
  it('labels every finding from pasted evidence as user-supplied and every flow step as unperformed', () => {
    const report = evaluate(saml(), NOW);
    expect(new Set(report.findings.map((f) => f.provenance))).toEqual(new Set(['user-supplied']));
    expect(new Set(report.flow.map((s) => s.provenance))).toEqual(new Set(['illustrative']));
  });

  it('carries published endpoints into the flow', () => {
    const report = evaluate(oidc(), NOW);
    expect(report.flow.find((s) => s.id === 'token')?.endpoint).toBe('https://op.example/token');
  });
});
