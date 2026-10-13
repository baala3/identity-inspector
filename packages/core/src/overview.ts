import type { Element } from '@xmldom/xmldom';
import { metadataOf } from './checks/oidc.js';
import { DS, MD } from './checks/saml.js';
import { message, SAML, SAMLP } from './checks/saml-response.js';
import { jwt, KIND_LABEL, kindOf } from './jwt.js';
import type { Evidence, Fact, OverviewSection, Workspace } from './model.js';
import { childElements, descendants, type Json, json, objects, strings, xml } from './parse.js';
import { decodeBase64, integerBits, parseCertificate } from './x509.js';

const text = (label: string, value: unknown): Fact[] =>
  value === undefined || value === null || value === ''
    ? []
    : [{ label, values: [String(value)], style: 'text' }];

const link = (label: string, value: unknown): Fact[] =>
  typeof value === 'string' && value ? [{ label, values: [value], style: 'link' }] : [];

const chips = (label: string, values: string[]): Fact[] =>
  values.length ? [{ label, values, style: 'chips' }] : [];

const section = (id: string, title: string, facts: Fact[]): OverviewSection[] =>
  facts.length ? [{ id, title, facts }] : [];

const OIDC_ENDPOINTS: Array<[string, string]> = [
  ['authorization_endpoint', 'Authorization'],
  ['token_endpoint', 'Token'],
  ['userinfo_endpoint', 'UserInfo'],
  ['jwks_uri', 'Signing keys (JWKS)'],
  ['end_session_endpoint', 'Logout'],
  ['revocation_endpoint', 'Revocation'],
  ['introspection_endpoint', 'Introspection'],
  ['registration_endpoint', 'Client registration'],
  ['device_authorization_endpoint', 'Device authorization'],
  ['pushed_authorization_request_endpoint', 'Pushed authorization requests'],
];

const SHOWN_CLAIMS = new Set([
  'iss',
  'sub',
  'aud',
  'azp',
  'client_id',
  'scope',
  'scp',
  'iat',
  'nbf',
  'exp',
]);

function rsaBits(key: Json): number | undefined {
  if (typeof key.n !== 'string') return undefined;
  try {
    return integerBits(decodeBase64(key.n.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    return undefined;
  }
}

const instant = (label: string, seconds: unknown): Fact[] =>
  typeof seconds === 'number' ? text(label, new Date(seconds * 1000).toISOString()) : [];

function oidc(
  metadata: Evidence | undefined,
  jwks: Evidence | undefined,
  token: Evidence | undefined,
): OverviewSection[] {
  const doc = (metadata && json(metadata)) ?? {};
  const oauth = metadata?.kind === 'oauth.metadata';
  const keys = objects((jwks && json(jwks))?.keys);
  const parsed = token && jwt(token).jwt;
  const { header = {}, claims = {} } = parsed ?? {};
  // Providers write scopes as a space-separated string or as a list, under either name.
  const listed = (value: unknown) =>
    typeof value === 'string' ? value.split(' ').filter(Boolean) : strings(value);
  const scopes = [...listed(claims.scope), ...listed(claims.scp)];
  return [
    ...section('token', parsed ? `Pasted ${KIND_LABEL[kindOf(parsed).kind]}` : 'Pasted token', [
      ...text('Type', header.typ),
      ...text('Algorithm', header.alg),
      ...text('Key ID', header.kid),
      ...text('Issuer', claims.iss),
      ...text('Subject', claims.sub),
      ...chips('Audience', typeof claims.aud === 'string' ? [claims.aud] : strings(claims.aud)),
      ...text('Issued to', claims.azp ?? claims.client_id),
      ...chips('Scopes', scopes),
      ...instant('Issued at', claims.iat),
      ...instant('Not before', claims.nbf),
      ...instant('Expires at', claims.exp),
      ...chips(
        'Other claims',
        Object.keys(claims).filter((claim) => !SHOWN_CLAIMS.has(claim)),
      ),
    ]),
    ...section('identity', oauth ? 'Authorization server' : 'Provider', [
      ...link('Issuer', doc.issuer),
      ...link(oauth ? 'Metadata document' : 'Discovery document', metadata?.source),
      ...chips('Subject types', strings(doc.subject_types_supported)),
    ]),
    ...section(
      'endpoints',
      'Endpoints',
      OIDC_ENDPOINTS.flatMap(([field, label]) => link(label, doc[field])),
    ),
    ...section('capabilities', 'What it supports', [
      ...chips('Scopes', strings(doc.scopes_supported)),
      ...chips('Response types', strings(doc.response_types_supported)),
      ...chips('Grant types', strings(doc.grant_types_supported)),
      ...chips('Response modes', strings(doc.response_modes_supported)),
      ...chips('Claims', strings(doc.claims_supported)),
    ]),
    ...section('security', 'Security settings', [
      ...chips('PKCE methods', strings(doc.code_challenge_methods_supported)),
      ...chips('ID token signing', strings(doc.id_token_signing_alg_values_supported)),
      ...chips('Client authentication', strings(doc.token_endpoint_auth_methods_supported)),
      ...chips(
        'Client authentication signing',
        strings(doc.token_endpoint_auth_signing_alg_values_supported),
      ),
      ...chips('Request object signing', strings(doc.request_object_signing_alg_values_supported)),
      ...chips('DPoP signing', strings(doc.dpop_signing_alg_values_supported)),
      ...text('Mutual-TLS-bound access tokens', doc.tls_client_certificate_bound_access_tokens),
      ...text('Pushed authorization requests required', doc.require_pushed_authorization_requests),
      ...text('Issuer in login response', doc.authorization_response_iss_parameter_supported),
    ]),
    ...section(
      'keys',
      `Signing keys (${keys.length})`,
      keys.map((key, index): Fact => {
        const bits = key.kty === 'RSA' ? rsaBits(key) : undefined;
        return {
          label: typeof key.kid === 'string' ? key.kid : `key ${index + 1}`,
          values: [
            String(key.kty ?? 'unknown type'),
            ...(bits ? [`${bits} bits`] : []),
            ...(typeof key.crv === 'string' ? [key.crv] : []),
            ...(typeof key.alg === 'string' ? [key.alg] : []),
            ...(typeof key.use === 'string' ? [`use: ${key.use}`] : []),
          ],
          style: 'chips',
        };
      }),
    ),
  ];
}

const ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';
const shortUrn = (value: string | null) => (value ?? '').split(':').pop() ?? '';
const scimName = (urn: string) => urn.replace('urn:ietf:params:scim:schemas:', '');

function samlResponse(evidence: Evidence | undefined): OverviewSection[] {
  const read = message(evidence);
  if (!read) return [];
  const { response } = read;
  const [assertion] = read.assertions;
  const first = (parent: Element | undefined, ns: string, name: string) =>
    parent ? descendants(parent, ns, name)[0] : undefined;
  const said = (element: Element | undefined) => element?.textContent?.trim();
  const nameId = first(assertion, SAML, 'NameID');
  const conditions = first(assertion, SAML, 'Conditions');
  const confirmation = first(assertion, SAML, 'SubjectConfirmationData');
  const statement = first(assertion, SAML, 'AuthnStatement');
  const attributes = assertion ? descendants(assertion, SAML, 'Attribute') : [];
  return [
    ...section('response', response ? 'Pasted response' : 'Pasted assertion', [
      ...text('Issuer', said(first(response ?? assertion, SAML, 'Issuer'))),
      ...text(
        'Status',
        shortUrn(first(response, SAMLP, 'StatusCode')?.getAttribute('Value') ?? null),
      ),
      ...link('Destination', response?.getAttribute('Destination')),
      ...text('In response to', response?.getAttribute('InResponseTo')),
      ...text('Issued at', (response ?? assertion)?.getAttribute('IssueInstant')),
      ...text(
        'Assertions',
        response && `${read.assertions.length} readable, ${read.encrypted.length} encrypted`,
      ),
    ]),
    ...section('assertion', 'Assertion', [
      ...text('Subject (NameID)', said(nameId)),
      ...text('NameID format', shortUrn(nameId?.getAttribute('Format') ?? null)),
      ...chips(
        'Audience',
        (assertion ? descendants(assertion, SAML, 'Audience') : []).flatMap((a) => said(a) ?? []),
      ),
      ...link('Recipient', confirmation?.getAttribute('Recipient')),
      ...text('Valid from', conditions?.getAttribute('NotBefore')),
      ...text('Valid until', conditions?.getAttribute('NotOnOrAfter')),
      ...text('Signed in at', statement?.getAttribute('AuthnInstant')),
      ...text('Session index', statement?.getAttribute('SessionIndex')),
      ...text(
        'Authentication context',
        shortUrn(said(first(statement, SAML, 'AuthnContextClassRef')) ?? null),
      ),
    ]),
    ...section(
      'attributes',
      `Attributes (${attributes.length})`,
      attributes.map(
        (attribute): Fact => ({
          label: attribute.getAttribute('FriendlyName') || attribute.getAttribute('Name') || '',
          values: childElements(attribute, SAML, 'AttributeValue').map((v) => said(v) ?? ''),
          style: 'chips',
        }),
      ),
    ),
  ];
}

function saml(metadata: Evidence | undefined): OverviewSection[] {
  const document = metadata && xml(metadata).document;
  const root = document?.documentElement;
  if (!document || !root) return [];
  const entity =
    root.localName === 'EntityDescriptor' ? root : descendants(document, MD, 'EntityDescriptor')[0];
  if (!entity) return [];

  const roles = (['IDPSSODescriptor', 'SPSSODescriptor'] as const).flatMap((name) =>
    childElements(entity, MD, name).map((element) => [name, element] as const),
  );
  const flag = (element: Element, name: string) =>
    element.hasAttribute(name) ? text(name, element.getAttribute(name)) : [];

  return [
    ...section('identity', 'Entity', [
      ...text('Entity ID', entity.getAttribute('entityID')),
      ...link('Metadata URL', metadata.source),
      ...chips(
        'Roles',
        roles.map(([name]) =>
          name === 'IDPSSODescriptor' ? 'Identity Provider' : 'Service Provider',
        ),
      ),
      ...text('Valid until', entity.getAttribute('validUntil') || root.getAttribute('validUntil')),
      ...chips(
        'NameID formats',
        descendants(entity, MD, 'NameIDFormat').map((f) => shortUrn(f.textContent?.trim() ?? '')),
      ),
    ]),
    ...section(
      'endpoints',
      'Endpoints',
      descendants(entity, MD, '*')
        .filter((element) => element.hasAttribute('Location'))
        .flatMap((element) =>
          link(
            `${element.localName} (${shortUrn(element.getAttribute('Binding'))})`,
            element.getAttribute('Location'),
          ),
        ),
    ),
    ...section(
      'security',
      'Signing requirements',
      roles.flatMap(([, element]) => [
        ...flag(element, 'WantAuthnRequestsSigned'),
        ...flag(element, 'AuthnRequestsSigned'),
        ...flag(element, 'WantAssertionsSigned'),
      ]),
    ),
    ...section(
      'keys',
      'Certificates',
      roles.flatMap(([, element]) =>
        childElements(element, MD, 'KeyDescriptor').flatMap((descriptor) =>
          descendants(descriptor, DS, 'X509Certificate').map((node): Fact => {
            const use = descriptor.getAttribute('use') || 'signing and encryption';
            try {
              const cert = parseCertificate(node.textContent ?? '');
              return {
                label: cert.subject || 'certificate',
                values: [
                  use,
                  `valid ${cert.notBefore.toISOString().slice(0, 10)} to ${cert.notAfter.toISOString().slice(0, 10)}`,
                  cert.keyBits ? `${cert.keyType} ${cert.keyBits} bits` : cert.keyType,
                  cert.signatureAlgorithm,
                ],
                style: 'chips',
              };
            } catch {
              return { label: 'unreadable certificate', values: [use], style: 'chips' };
            }
          }),
        ),
      ),
    ),
    ...section('capabilities', 'Attributes', [
      ...chips(
        'Offered by the IdP',
        descendants(entity, ASSERTION, 'Attribute').map(
          (a) => a.getAttribute('FriendlyName') || a.getAttribute('Name') || '',
        ),
      ),
      ...chips(
        'Requested by the SP',
        descendants(entity, MD, 'RequestedAttribute').map(
          (a) => a.getAttribute('FriendlyName') || a.getAttribute('Name') || '',
        ),
      ),
    ]),
  ];
}

function scimResources(evidence: Evidence | undefined): Json[] {
  if (evidence?.fetch?.status !== 200) return [];
  const doc = json(evidence);
  if (doc) return objects(doc.Resources);
  try {
    return objects(JSON.parse(evidence.raw));
  } catch {
    return [];
  }
}

function scim(workspace: Workspace): OverviewSection[] {
  const find = (kind: Evidence['kind']) => workspace.evidence.find((e) => e.kind === kind);
  const configEvidence = find('scim.service-provider-config');
  const config = (configEvidence?.fetch?.status === 200 && json(configEvidence)) || undefined;
  const feature = (name: string, label: string, limit?: string): Fact[] => {
    const value = config?.[name] as Json | undefined;
    if (!value) return [];
    const extra = limit && value[limit] !== undefined ? `, ${limit} ${String(value[limit])}` : '';
    return text(label, `${value.supported === true ? 'yes' : 'no'}${extra}`);
  };
  return [
    ...section('identity', 'Server', [
      ...link('Base URL', workspace.target.input),
      ...link('Documentation', config?.documentationUri),
      ...chips(
        'Authentication',
        objects(config?.authenticationSchemes).map((s) => String(s.name ?? s.type ?? '?')),
      ),
    ]),
    ...section('capabilities', 'Features it claims', [
      ...feature('patch', 'PATCH'),
      ...feature('filter', 'Filtering', 'maxResults'),
      ...feature('bulk', 'Bulk operations', 'maxOperations'),
      ...feature('sort', 'Sorting'),
      ...feature('etag', 'ETags'),
      ...feature('changePassword', 'Password change'),
    ]),
    ...section(
      'endpoints',
      'Resource types',
      scimResources(find('scim.resource-types')).map(
        (type): Fact => ({
          label: `${String(type.name)} at ${String(type.endpoint)}`,
          values: [
            String(type.schema),
            ...objects(type.schemaExtensions).map((x) => String(x.schema)),
          ].map(scimName),
          style: 'chips',
        }),
      ),
    ),
    ...section(
      'schemas',
      'Schemas',
      scimResources(find('scim.schemas')).flatMap((schema) =>
        chips(
          scimName(String(schema.id)),
          objects(schema.attributes).map((a) => String(a.name)),
        ),
      ),
    ),
  ];
}

/** What the evidence states about the target, restated without a verdict. */
export function overviewFor(workspace: Workspace): OverviewSection[] {
  // An error response is not something the target publishes, whatever its body says.
  const find = (kind: Evidence['kind']) =>
    workspace.evidence.find((e) => e.kind === kind && (!e.fetch || e.fetch.status === 200));
  if (workspace.target.protocol === 'oidc' || workspace.target.protocol === 'oauth') {
    const metadata = metadataOf(workspace);
    return oidc(metadata && find(metadata.kind), find('oidc.jwks'), find('oidc.token'));
  }
  if (workspace.target.protocol === 'saml')
    return [...samlResponse(find('saml.response')), ...saml(find('saml.metadata'))];
  return scim(workspace);
}

const UNSEEN_SERVER = [
  'How long an authorization code lives, and whether it can be used twice',
  'Whether PKCE is enforced, or only accepted when a client sends it',
  'How strictly redirect URIs are matched',
  'Whether refresh tokens are rotated',
  'Which clients may use each grant and each authentication method',
  'Whether the server behaves as its metadata says',
];

const UNSEEN: Record<Workspace['target']['protocol'], string[]> = {
  oidc: UNSEEN_SERVER,
  oauth: UNSEEN_SERVER,
  saml: [
    'Whether real responses are signed the way the metadata says, and with which algorithm',
    'Which NameID and attributes a real response carries',
    'How much clock skew is tolerated',
    'Whether a response is accepted more than once',
    'Whether the party behaves as its metadata says',
  ],
  scim: [
    'Whether the filters, PATCH operations, and pagination it advertises actually work',
    'Which attributes are accepted on write, beyond those in the published schemas',
    'Whether a user is removed or only deactivated when deprovisioned',
    'Rate limits, and how the server answers when they are reached',
    'Whether the server behaves as its configuration says',
  ],
};

/**
 * What documents of the kind gathered can never show, so that silence is not read as a pass.
 * Empty when nothing a target publishes was read: there is then nothing to qualify.
 */
export function unseenFor(workspace: Workspace): string[] {
  const published = workspace.evidence.some(
    (e) => e.fetch?.status === 200 || e.kind === 'saml.metadata',
  );
  return published ? UNSEEN[workspace.target.protocol] : [];
}
