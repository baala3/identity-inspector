import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { checks, evaluate } from '../src/engine.js';
import type { Evidence, EvidenceKind, Severity, Workspace } from '../src/model.js';
import { identity, sign } from './support/saml.js';

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

// --- ID token -----------------------------------------------------------

const SECONDS = NOW.getTime() / 1000;
const CLAIMS: Doc = {
  iss: 'https://op.example',
  sub: 'user-1',
  aud: 'client-1',
  iat: SECONDS - 60,
  exp: SECONDS + 3600,
  nonce: 'n-1',
};

const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

const signer = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
  'sign',
  'verify',
]);
const { kty, crv, x, y } = await crypto.subtle.exportKey('jwk', signer.publicKey);
const TOKEN_KEY: Doc = { kty, crv, x, y, kid: 'es', use: 'sig' };

/** A token signed by the key the fixture provider publishes as kid "es". */
async function signed(claims: Doc = {}, header: Doc = {}): Promise<string> {
  const input = `${segment({ alg: 'ES256', kid: 'es', ...header })}.${segment({ ...CLAIMS, ...claims })}`;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signer.privateKey,
    Buffer.from(input),
  );
  return `${input}.${Buffer.from(signature).toString('base64url')}`;
}

/** A token whose signature nothing here can check: unsigned, or signed with a shared secret. */
const unverifiable = (alg: string) => `${segment({ alg })}.${segment(CLAIMS)}.c2ln`;

function withToken(raw: string, o: OidcOptions = {}): Workspace {
  const workspace = oidc({
    keys: [...KEYS, TOKEN_KEY],
    ...o,
    discovery: { id_token_signing_alg_values_supported: ['RS256', 'ES256'], ...o.discovery },
  });
  workspace.evidence.unshift({
    id: 'oidc.token',
    kind: 'oidc.token',
    provenance: 'user-supplied',
    raw,
  });
  return workspace;
}

const TOKEN = await signed();

const ACCESS_CLAIMS: Doc = {
  nonce: undefined,
  client_id: 'client-1',
  jti: 'j-1',
  scope: 'read write',
};
/** An access token that says so, as RFC 9068 asks. */
const ACCESS_TOKEN = await signed(ACCESS_CLAIMS, { typ: 'at+jwt' });
/** An access token that can only be recognised by its scope claim. */
const UNMARKED_ACCESS_TOKEN = await signed(ACCESS_CLAIMS);
const [HEAD = '', , TAIL = ''] = TOKEN.split('.');
const ALTERED = `${HEAD}.${segment({ ...CLAIMS, sub: 'someone-else' })}.${TAIL}`;

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

// --- SAML response ------------------------------------------------------

const IDP = identity('idp.example', ['-newkey', 'rsa:2048']);
const STRANGER = identity('stranger.example', ['-newkey', 'rsa:2048']);
const IDP_METADATA = samlXml({ keys: key(IDP.cert) });

interface ResponseOptions {
  /** The last part of the status URN, with an optional second level and message. */
  status?: string;
  secondStatus?: string;
  statusMessage?: string;
  version?: string;
  /** Replaces the assertion, or removes it when empty. */
  assertions?: string;
  conditions?: string;
  subject?: string;
}

const STATUS = 'urn:oasis:names:tc:SAML:2.0:status:';
const BEARER_DATA =
  'Recipient="https://sp.example/acs" NotOnOrAfter="2027-06-01T00:05:00Z" InResponseTo="_req1"';
const bearer = (data = BEARER_DATA) =>
  `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData ${data}/></saml:SubjectConfirmation>`;
const conditions = (attrs: string, audience = 'https://sp.example/metadata') =>
  `<saml:Conditions ${attrs}>${audience ? `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>` : ''}</saml:Conditions>`;

function assertionXml(o: ResponseOptions = {}, id = '_a1'): string {
  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="2027-06-01T00:00:00Z"><saml:Issuer>https://idp.example/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>${
    o.subject ?? bearer()
  }</saml:Subject>${
    o.conditions ??
    conditions('NotBefore="2027-05-31T23:59:00Z" NotOnOrAfter="2027-06-01T00:05:00Z"')
  }<saml:AuthnStatement AuthnInstant="2027-06-01T00:00:00Z" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="urn:oid:2.5.4.42" FriendlyName="givenName"><saml:AttributeValue>Ada</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>staff</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
}

function responseXml(o: ResponseOptions = {}): string {
  const second = o.secondStatus ? `<samlp:StatusCode Value="${STATUS}${o.secondStatus}"/>` : '';
  const said = o.statusMessage
    ? `<samlp:StatusMessage>${o.statusMessage}</samlp:StatusMessage>`
    : '';
  return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="${o.version ?? '2.0'}" IssueInstant="2027-06-01T00:00:00Z" Destination="https://sp.example/acs" InResponseTo="_req1"><saml:Issuer>https://idp.example/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="${STATUS}${o.status ?? 'Success'}">${second}</samlp:StatusCode>${said}</samlp:Status>${
    o.assertions ?? assertionXml(o)
  }</samlp:Response>`;
}

/** A workspace holding a pasted response, with the IdP metadata beside it when given. */
function response(raw: string, metadata?: string): Workspace {
  const evidence: Evidence[] = [
    { id: 'saml.response', kind: 'saml.response', provenance: 'user-supplied', raw },
  ];
  if (metadata) {
    evidence.push({
      id: 'saml.metadata',
      kind: 'saml.metadata',
      provenance: 'user-supplied',
      raw: metadata,
    });
  }
  return { target: { protocol: 'saml', input: 'https://idp.example/metadata' }, evidence };
}

const SIGNED_ASSERTION = sign(responseXml(), IDP, { element: 'Assertion' });
const SIGNED_RESPONSE = sign(responseXml(), IDP, { element: 'Response' });
const SHA1 = {
  signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
  digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
};

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

  'oidc.token.format': [
    [withToken(TOKEN), 'pass'],
    [withToken(`${segment({})}.bm90.c2ln`), 'error', /payload does not decode/],
    [withToken(`${segment({ alg: 'RSA-OAEP' })}.a2V5.aXY.Y2lwaGVy.dGFn`), 'error', /encrypted/],
  ],
  'oidc.token.kind': [
    [withToken(TOKEN), 'info', /an ID token because it carries "nonce"/],
    [
      withToken(ACCESS_TOKEN),
      'info',
      /an access token because its header declares "typ": "at\+jwt"\.$/,
    ],
    [withToken(UNMARKED_ACCESS_TOKEN), 'info', /carries "scope".*That is an inference/],
    [withToken(await signed({ nonce: undefined })), 'info', /nothing in it marks it/],
  ],
  'oidc.token.alg': [
    [withToken(TOKEN), 'pass', /provider advertises/],
    [withToken(unverifiable('none')), 'error', /unsigned/],
    [withToken(unverifiable('HS256')), 'error', /does not advertise/],
    // Discovery says nothing about how access tokens are signed, so there is nothing to compare.
    [
      withToken(ACCESS_TOKEN, { discovery: { id_token_signing_alg_values_supported: ['RS256'] } }),
      'pass',
      /signed with ES256\.$/,
    ],
    [
      withToken(unverifiable('HS256'), {
        discovery: { id_token_signing_alg_values_supported: ['RS256', 'HS256'] },
      }),
      'warn',
      /shared-secret/,
    ],
  ],
  'oidc.token.key': [
    [withToken(TOKEN), 'pass'],
    [
      withToken(await signed({}, { kid: 'gone' })),
      'error',
      /does not publish \(it publishes a, b, es\)/,
    ],
    [withToken(await signed({}, { kid: 'a' })), 'error', /cannot sign with ES256/],
    [withToken(await signed({}, { kid: undefined })), 'info', /Only one published key/],
    [
      withToken(await signed({}, { kid: undefined }), {
        keys: [TOKEN_KEY, { ...TOKEN_KEY, kid: 'es-2' }],
      }),
      'warn',
      /2 published keys fit/,
    ],
  ],
  'oidc.token.signature': [
    [withToken(TOKEN), 'pass', /verifies with ES256 against kid "es"/],
    [withToken(await signed({}, { kid: undefined })), 'pass'],
    [withToken(ALTERED), 'error', /does not verify/],
    [withToken(unverifiable('HS256')), 'info', /client secret/],
    [withToken(TOKEN, { keys: KEYS }), 'info', /no published key fits/],
  ],
  'oidc.token.issuer': [
    [withToken(TOKEN), 'pass'],
    [withToken(await signed({ iss: 'https://op.example/' })), 'error', /trailing slash/],
  ],
  'oidc.id-token.required-claims': [
    [withToken(TOKEN), 'pass'],
    [
      withToken(await signed({ sub: undefined, exp: '1900000000' })),
      'error',
      /"sub" is missing, "exp" is not a number/,
    ],
  ],
  'oidc.access-token.required-claims': [
    [withToken(ACCESS_TOKEN), 'pass'],
    [
      withToken(await signed({ ...ACCESS_CLAIMS, sub: undefined, jti: 7 }, { typ: 'at+jwt' })),
      'error',
      /"sub" is missing, "jti" is not a string/,
    ],
    [withToken(UNMARKED_ACCESS_TOKEN), 'info', /no standard says/],
  ],
  'oidc.token.time': [
    [withToken(TOKEN), 'pass', /in 1 hour/],
    [
      withToken(TOKEN),
      'warn',
      /expired at 2027-06-01T01:00:00.000Z, 2 days before/,
      new Date('2027-06-03T01:00:00Z'),
    ],
    [withToken(await signed({ nbf: SECONDS + 600 })), 'error', /not valid until/],
    [withToken(await signed({ iat: SECONDS + 1200 })), 'warn', /One of the two clocks/],
  ],
  'oidc.id-token.audience': [
    [withToken(TOKEN), 'info', /addressed to client-1/],
    [withToken(await signed({ aud: ['client-1', 'api'] })), 'warn', /no "azp"/],
    [
      withToken(await signed({ aud: ['client-1', 'api'], azp: 'client-1' })),
      'info',
      /issued to client-1/,
    ],
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
  'saml.response.well-formed': [
    [response(SIGNED_ASSERTION), 'pass', /Response carrying 1 assertion\./],
    [response(assertionXml()), 'pass', /Assertion on its own/],
    [
      response('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'),
      'error',
      /cannot be read/,
    ],
    [response('<Response/>'), 'error', /not a SAML 2.0 Response or Assertion/],
    [
      response(`<!DOCTYPE r [<!ENTITY e "x">]>${responseXml()}`),
      'error',
      /DTD or entities, which are refused/,
    ],
    [response(responseXml({ version: '1.1' })), 'error', /version "1.1"/],
  ],
  'saml.response.status': [
    [response(responseXml()), 'pass'],
    [
      response(
        responseXml({
          status: 'Responder',
          secondStatus: 'RequestDenied',
          statusMessage: 'User is not assigned to this application',
          assertions: '',
        }),
      ),
      'error',
      /reports Responder \(RequestDenied\), not Success, and says: "User is not assigned/,
    ],
  ],
  'saml.assertion.readable': [
    [response(responseXml()), 'pass'],
    [
      response(responseXml({ assertions: assertionXml() + assertionXml({}, '_a2') })),
      'warn',
      /2 assertions/,
    ],
    [
      response(responseXml({ assertions: '<saml:EncryptedAssertion/>' })),
      'info',
      /encrypted for the SP/,
    ],
    [
      response(responseXml({ status: 'Responder', assertions: '' })),
      'info',
      /carries no assertion/,
    ],
  ],
  'saml.response.signed': [
    [response(SIGNED_ASSERTION), 'pass', /assertion is signed\. The Response around it is not/],
    [response(SIGNED_RESPONSE), 'pass', /covers the assertion inside it/],
    [response(sign(SIGNED_ASSERTION, IDP, { element: 'Response' })), 'pass', /Both/],
    [response(responseXml()), 'error', /Neither/],
  ],
  'saml.response.signature-reference': [
    [response(SIGNED_ASSERTION), 'pass'],
    // The signed assertion is given a new ID, so its signature now points at nothing it sits in.
    [
      response(SIGNED_ASSERTION.replace('ID="_a1"', 'ID="_forged"')),
      'error',
      /refers to "#_a1" instead/,
    ],
    // A second element takes the signed ID, which is how a wrapped copy hides.
    [
      response(
        SIGNED_ASSERTION.replace('</samlp:Response>', '<saml:Advice ID="_a1"/></samlp:Response>'),
      ),
      'error',
      /2 elements share the ID "_a1"/,
    ],
  ],
  'saml.response.signature': [
    [
      response(SIGNED_ASSERTION, IDP_METADATA),
      'pass',
      /verifies against the certificate "idp.example" that the IdP publishes/,
    ],
    [response(SIGNED_RESPONSE, IDP_METADATA), 'pass', /signature on the Response verifies/],
    [response(SIGNED_ASSERTION), 'info', /does not show who signed it/],
    [
      response(SIGNED_ASSERTION.replace('user@example.com', 'admin@example.com'), IDP_METADATA),
      'error',
      /changed after it was signed/,
    ],
    [
      response(sign(responseXml(), STRANGER, { element: 'Assertion' }), IDP_METADATA),
      'error',
      /"stranger.example" carried inside the message, which is not one the IdP publishes/,
    ],
  ],
  'saml.response.signature-algorithm': [
    [response(SIGNED_ASSERTION), 'pass', /rsa-sha256 over a sha256 digest/],
    [response(sign(responseXml(), IDP, { element: 'Assertion', ...SHA1 })), 'warn', /SHA-1/],
  ],
  'saml.response.issuer': [
    [response(SIGNED_ASSERTION, IDP_METADATA), 'pass'],
    [
      response(
        SIGNED_ASSERTION,
        samlXml({ keys: key(IDP.cert), entityAttrs: 'entityID="https://other.example/metadata"' }),
      ),
      'error',
      /metadata describes https:\/\/other.example\/metadata/,
    ],
  ],
  'saml.assertion.time': [
    [response(responseXml()), 'pass', /in 5 minutes/],
    [
      response(responseXml()),
      'warn',
      /expired at 2027-06-01T00:05:00.000Z, 1 hour before/,
      new Date('2027-06-01T01:05:00Z'),
    ],
    [response(responseXml()), 'error', /SP clock is behind/, new Date('2027-05-31T23:58:00Z')],
    [response(responseXml({ conditions: conditions('') })), 'warn', /no NotOnOrAfter/],
  ],
  'saml.assertion.audience': [
    [response(responseXml()), 'info', /addressed to https:\/\/sp.example\/metadata/],
    [
      response(responseXml({ conditions: conditions('NotOnOrAfter="2027-06-01T00:05:00Z"', '') })),
      'warn',
      /names no Audience/,
    ],
  ],
  'saml.assertion.subject-confirmation': [
    [response(responseXml()), 'pass', /in response to request _req1/],
    [
      response(responseXml({ subject: bearer('NotOnOrAfter="2027-06-01T00:05:00Z"') })),
      'error',
      /it has no Recipient/,
    ],
    [response(responseXml({ subject: '' })), 'error', /no bearer SubjectConfirmation/],
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
        it(`scenario ${index + 1} yields ${severity}${detail ? ` matching ${detail}` : ''}`, async () => {
          const found = (await evaluate(workspace, instant ?? NOW)).findings.filter(
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
    ['oidc with a pasted ID token', withToken(TOKEN)],
    ['oidc with a pasted access token', withToken(ACCESS_TOKEN)],
    ['saml idp', saml()],
    ['saml sp', saml({ role: 'sp' })],
    ['saml response with the IdP metadata', response(SIGNED_ASSERTION, IDP_METADATA)],
    ['scim', scim()],
  ])('%s raises no errors or warnings', async (_name, workspace) => {
    const { summary } = await evaluate(workspace, NOW);
    expect([summary.error, summary.warn]).toEqual([0, 0]);
  });
});

describe('report', () => {
  it('labels every finding from pasted evidence as user-supplied and every flow step as unperformed', async () => {
    const report = await evaluate(saml(), NOW);
    expect(new Set(report.findings.map((f) => f.provenance))).toEqual(new Set(['user-supplied']));
    expect(new Set(report.flow.map((s) => s.provenance))).toEqual(new Set(['illustrative']));
  });

  it('carries published endpoints into the flow', async () => {
    const report = await evaluate(oidc(), NOW);
    expect(report.flow.find((s) => s.id === 'token')?.endpoint).toBe('https://op.example/token');
  });
});

describe('overview', () => {
  const facts = async (workspace: Workspace) =>
    Object.fromEntries(
      (await evaluate(workspace, NOW)).overview.flatMap((s) =>
        s.facts.map((f) => [`${s.id}/${f.label}`, f.values]),
      ),
    );

  it('restates what an OpenID Provider publishes', async () => {
    expect(await facts(oidc())).toMatchObject({
      'identity/Issuer': ['https://op.example'],
      'endpoints/Token': ['https://op.example/token'],
      'capabilities/Scopes': ['openid', 'email'],
      'security/PKCE methods': ['S256'],
      'keys/a': ['RSA', '2048 bits', 'use: sig'],
    });
  });

  it('restates what SAML metadata publishes', async () => {
    expect(await facts(saml())).toMatchObject({
      'identity/Entity ID': ['https://idp.example/metadata'],
      'identity/Roles': ['Identity Provider'],
      'identity/NameID formats': ['emailAddress'],
      'endpoints/SingleSignOnService (HTTP-Redirect)': ['https://idp.example/sso'],
      'keys/idp.example': [
        'signing',
        'valid 2025-01-01 to 2030-01-01',
        'RSA 2048 bits',
        'sha256WithRSAEncryption',
      ],
    });
  });

  it('restates what a pasted SAML response says, ahead of the metadata', async () => {
    const report = await evaluate(response(SIGNED_ASSERTION, IDP_METADATA), NOW);
    expect(report.overview.map((s) => s.id).slice(0, 4)).toEqual([
      'response',
      'assertion',
      'attributes',
      'identity',
    ]);
    expect(await facts(response(SIGNED_ASSERTION))).toMatchObject({
      'response/Status': ['Success'],
      'response/Destination': ['https://sp.example/acs'],
      'assertion/Subject (NameID)': ['user@example.com'],
      'assertion/NameID format': ['emailAddress'],
      'assertion/Audience': ['https://sp.example/metadata'],
      'assertion/Authentication context': ['PasswordProtectedTransport'],
      'attributes/givenName': ['Ada'],
      'attributes/groups': ['admins', 'staff'],
    });
  });

  it('restates what a SCIM server publishes', async () => {
    expect(await facts(scim())).toMatchObject({
      'capabilities/PATCH': ['yes'],
      'capabilities/Filtering': ['yes, maxResults 200'],
      'endpoints/User at /Users': ['core:2.0:User', 'extension:enterprise:2.0:User'],
      'schemas/core:2.0:User': ['userName'],
    });
  });

  it('restates the claims of a pasted token', async () => {
    expect(await facts(withToken(TOKEN))).toMatchObject({
      'token/Algorithm': ['ES256'],
      'token/Key ID': ['es'],
      'token/Subject': ['user-1'],
      'token/Audience': ['client-1'],
      'token/Expires at': ['2027-06-01T01:00:00.000Z'],
      'token/Other claims': ['nonce'],
    });
  });

  it('restates an access token as one, with its client and scopes', async () => {
    const report = await evaluate(withToken(ACCESS_TOKEN), NOW);
    expect(report.overview[0]?.title).toBe('Pasted access token');
    expect(await facts(withToken(ACCESS_TOKEN))).toMatchObject({
      'token/Type': ['at+jwt'],
      'token/Issued to': ['client-1'],
      'token/Scopes': ['read', 'write'],
    });
  });

  it('reads scopes written as a list as well as a string', async () => {
    const token = await signed({ ...ACCESS_CLAIMS, scope: ['read', 'write'] });
    expect(await facts(withToken(token))).toMatchObject({ 'token/Scopes': ['read', 'write'] });
  });

  it('judges an access token by its own rules, not by those for ID tokens', async () => {
    const ids = (await evaluate(withToken(ACCESS_TOKEN), NOW)).findings.map((f) => f.checkId);
    expect(ids).toContain('oidc.access-token.required-claims');
    expect(ids.filter((id) => id.startsWith('oidc.id-token.'))).toEqual([]);
  });

  it('is empty rather than wrong when nothing could be read', async () => {
    const unreachable = await evaluate(oidc({ discoveryStatus: 404, jwksStatus: 404 }), NOW);
    expect(unreachable.overview.map((s) => s.id)).not.toContain('endpoints');
    expect((await evaluate(pasted('<broken'), NOW)).overview).toEqual([]);
  });
});
