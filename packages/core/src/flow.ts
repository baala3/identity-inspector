import { MD } from './checks/saml.js';
import type { FlowStep, Workspace } from './model.js';
import { descendants, json, xml } from './parse.js';

type Draft = Omit<FlowStep, 'provenance' | 'endpoint'> & { endpoint?: unknown };

/**
 * Nothing here has been performed: every step is illustrative until a probe or
 * a live flow replaces it. Only the endpoint is real, and only when the target
 * published it.
 */
function illustrate(steps: Draft[]): FlowStep[] {
  return steps.map(({ endpoint, ...step }) => ({
    ...step,
    provenance: 'illustrative',
    ...(typeof endpoint === 'string' && { endpoint }),
  }));
}

export function flowFor(workspace: Workspace): FlowStep[] {
  const { protocol } = workspace.target;
  const find = (kind: string) => workspace.evidence.find((e) => e.kind === kind);

  if (protocol === 'oidc') {
    const discovery = find('oidc.discovery');
    const doc = (discovery && json(discovery)) ?? {};
    return illustrate([
      {
        id: 'authorize',
        from: 'Browser',
        to: 'OP',
        label: 'Authorization request with code_challenge',
        endpoint: doc.authorization_endpoint,
        concerns: ['oidc.discovery.code-flow', 'oidc.discovery.pkce', 'oidc.discovery.implicit'],
      },
      {
        id: 'redirect',
        from: 'OP',
        to: 'RP',
        label: 'Redirect with code and state',
        concerns: ['oidc.discovery.iss-parameter'],
      },
      {
        id: 'token',
        from: 'RP',
        to: 'OP',
        label: 'Token request with code_verifier',
        endpoint: doc.token_endpoint,
        concerns: ['oidc.discovery.password-grant'],
      },
      {
        id: 'keys',
        from: 'RP',
        to: 'OP',
        label: 'Fetch keys and verify the ID token',
        endpoint: doc.jwks_uri,
        concerns: [
          'oidc.jwks',
          'oidc.id-token',
          'oidc.discovery.rs256',
          'oidc.discovery.alg-none',
          'oidc.discovery.issuer',
        ],
      },
      {
        id: 'userinfo',
        from: 'RP',
        to: 'OP',
        label: 'UserInfo request',
        endpoint: doc.userinfo_endpoint,
        concerns: ['oidc.discovery.openid-scope'],
      },
    ]);
  }

  if (protocol === 'saml') {
    const metadata = find('saml.metadata');
    const document = metadata && xml(metadata).document;
    const location = (name: string) =>
      document ? descendants(document, MD, name)[0]?.getAttribute('Location') : undefined;
    return illustrate([
      {
        id: 'authn-request',
        from: 'SP',
        to: 'IdP',
        label: 'AuthnRequest via the browser',
        endpoint: location('SingleSignOnService'),
        concerns: ['saml.idp.sso-service', 'saml.idp.want-authn-requests-signed'],
      },
      { id: 'authenticate', from: 'Browser', to: 'IdP', label: 'User authenticates', concerns: [] },
      {
        id: 'response',
        from: 'IdP',
        to: 'SP',
        label: 'Signed Response posted to the ACS',
        endpoint: location('AssertionConsumerService'),
        concerns: ['saml.sp', 'saml.metadata.nameid-formats'],
      },
      {
        id: 'verify',
        from: 'SP',
        to: 'SP',
        label: 'Verify signature against published certificate',
        concerns: ['saml.idp.signing-key', 'saml.cert', 'saml.metadata.valid-until'],
      },
    ]);
  }

  const base = workspace.target.input.replace(/\/$/, '');
  return illustrate([
    {
      id: 'discover',
      from: 'SCIM client',
      to: 'SCIM server',
      label: 'Read ServiceProviderConfig, ResourceTypes, Schemas',
      endpoint: `${base}/ServiceProviderConfig`,
      concerns: [
        'scim.discovery',
        'scim.config.schema',
        'scim.config.auth-schemes',
        'scim.resource-types',
        'scim.schemas',
        'scim.error',
      ],
    },
    {
      id: 'match',
      from: 'SCIM client',
      to: 'SCIM server',
      label: 'GET /Users?filter=userName eq ...',
      endpoint: `${base}/Users`,
      concerns: ['scim.config.filter'],
    },
    {
      id: 'create',
      from: 'SCIM client',
      to: 'SCIM server',
      label: 'POST /Users',
      endpoint: `${base}/Users`,
      concerns: ['scim.schemas.enterprise-extension'],
    },
    {
      id: 'update',
      from: 'SCIM client',
      to: 'SCIM server',
      label: 'PATCH /Users/{id}, including active=false',
      endpoint: `${base}/Users/{id}`,
      concerns: ['scim.config.patch'],
    },
  ]).map((step) =>
    // The discovery requests are the one thing this inspection really sent.
    step.id === 'discover' ? { ...step, provenance: 'executed' as const } : step,
  );
}
