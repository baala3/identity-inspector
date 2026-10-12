import type { Check, CheckContext, Citation, Evidence, Outcome } from '../model.js';
import { isHttps, type Json, json, objects, strings } from '../parse.js';
import { decodeBase64, integerBits, parseCertificate } from '../x509.js';

const DISCOVERY: Citation = {
  label: 'OpenID Connect Discovery 1.0, section 3',
  url: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
};
const DISCOVERY_VALIDATION: Citation = {
  label: 'OpenID Connect Discovery 1.0, section 4.3',
  url: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation',
};
const DISCOVERY_RESPONSE: Citation = {
  label: 'OpenID Connect Discovery 1.0, section 4.2',
  url: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse',
};
const BCP = (section: string): Citation => ({
  label: `RFC 9700 (OAuth 2.0 Security BCP), section ${section}`,
  url: `https://www.rfc-editor.org/rfc/rfc9700#section-${section}`,
});
const JWK = (section: string): Citation => ({
  label: `RFC 7517 (JSON Web Key), section ${section}`,
  url: `https://www.rfc-editor.org/rfc/rfc7517#section-${section}`,
});
const JWA = (section: string): Citation => ({
  label: `RFC 7518 (JSON Web Algorithms), section ${section}`,
  url: `https://www.rfc-editor.org/rfc/rfc7518#section-${section}`,
});

const find = (ctx: CheckContext, kind: Evidence['kind']) =>
  ctx.workspace.evidence.find((e) => e.kind === kind);

/** Runs a check body against the discovery document, when one was retrieved and parsed. */
function onDiscovery(
  body: (doc: Json, evidence: Evidence, ctx: CheckContext) => Outcome | Outcome[] | undefined,
): Check['run'] {
  return (ctx) => {
    const evidence = find(ctx, 'oidc.discovery');
    const doc = evidence && json(evidence);
    return evidence && doc ? body(doc, evidence, ctx) : undefined;
  };
}

function onJwks(
  body: (keys: Json[], evidence: Evidence, ctx: CheckContext) => Outcome | Outcome[] | undefined,
): Check['run'] {
  return (ctx) => {
    const evidence = find(ctx, 'oidc.jwks');
    const doc = evidence && json(evidence);
    return evidence && doc ? body(objects(doc.keys), evidence, ctx) : undefined;
  };
}

function reachable(kind: Evidence['kind'], what: string): Check['run'] {
  return (ctx) => {
    const evidence = find(ctx, kind);
    if (!evidence?.fetch) return undefined;
    const { status, error } = evidence.fetch;
    if (status === 200 && json(evidence)) {
      return { severity: 'pass', detail: `${what} returned 200 with a JSON object.`, evidence };
    }
    const why =
      status === 0
        ? `request failed: ${error ?? 'no response'}`
        : status === 200
          ? 'the body is not a JSON object'
          : `HTTP ${status}`;
    return {
      severity: 'error',
      detail: `${what} at ${evidence.source} is unusable: ${why}.`,
      evidence,
    };
  };
}

const ENDPOINT_FIELDS = [
  'authorization_endpoint',
  'token_endpoint',
  'userinfo_endpoint',
  'jwks_uri',
  'registration_endpoint',
  'end_session_endpoint',
  'revocation_endpoint',
  'introspection_endpoint',
  'device_authorization_endpoint',
  'pushed_authorization_request_endpoint',
];

/** Family of signature algorithms a JWK can serve, by key type. */
function algFamily(alg: string): string | undefined {
  if (/^(RS|PS)\d+$/.test(alg)) return 'RSA';
  if (/^ES\d+K?$/.test(alg)) return 'EC';
  if (alg === 'EdDSA') return 'OKP';
  if (/^HS\d+$/.test(alg)) return 'oct';
  return undefined;
}

const keyLabel = (key: Json, index: number) =>
  typeof key.kid === 'string' ? `kid "${key.kid}"` : `key #${index}`;

export const oidcChecks: Check[] = [
  {
    id: 'oidc.discovery.reachable',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Discovery document',
    citation: DISCOVERY_RESPONSE,
    remediation: {
      op: 'Serve the provider configuration at {issuer}/.well-known/openid-configuration with a 200.',
      rp: 'Confirm the issuer value with the tenant admin; it is often tenant-specific.',
    },
    run: reachable('oidc.discovery', 'The discovery document'),
  },
  {
    id: 'oidc.discovery.content-type',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Discovery document content type',
    citation: DISCOVERY_RESPONSE,
    remediation: { op: 'Set Content-Type: application/json on the discovery response.' },
    run: (ctx) => {
      const evidence = find(ctx, 'oidc.discovery');
      if (evidence?.fetch?.status !== 200) return undefined;
      const type = evidence.fetch.headers['content-type'] ?? '';
      return /^application\/json\b/i.test(type)
        ? { severity: 'pass', detail: `Content-Type is ${type}.`, evidence }
        : {
            severity: 'warn',
            detail: `Content-Type is "${type || '(none)'}". It should be application/json, and strict clients reject anything else.`,
            evidence,
          };
    },
  },
  {
    id: 'oidc.discovery.issuer-match',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Issuer value',
    citation: DISCOVERY_VALIDATION,
    remediation: {
      op: 'Return an issuer that is exactly the URL the discovery document sits under.',
      rp: 'Copy the issuer exactly as the provider returns it, including any trailing slash.',
    },
    run: onDiscovery((doc, evidence, ctx) => {
      const asked = ctx.workspace.target.input;
      const got = doc.issuer;
      if (typeof got !== 'string') {
        return {
          severity: 'error',
          detail: 'The document has no issuer.',
          evidence,
          pointer: '/issuer',
        };
      }
      // A template can never match; oidc.discovery.issuer-templated reports it.
      if (/[{}]/.test(got)) return undefined;
      if (got === asked) {
        return {
          severity: 'pass',
          detail: `The issuer is ${got}, the same URL you entered.`,
          evidence,
          pointer: '/issuer',
        };
      }
      if (got.replace(/\/$/, '') === asked.replace(/\/$/, '')) {
        return {
          severity: 'info',
          detail: `The provider calls itself ${got}. You entered ${asked}. The only difference is a trailing slash, but apps compare this value exactly, so configure your app with ${got}.`,
          evidence,
          pointer: '/issuer',
        };
      }
      return {
        severity: 'error',
        detail: `The provider calls itself ${got}, but this document was fetched for ${asked}. The two must be identical, so most OIDC libraries will refuse to use this provider.`,
        evidence,
        pointer: '/issuer',
      };
    }),
  },
  {
    id: 'oidc.discovery.issuer-templated',
    protocol: 'oidc',
    category: 'interop',
    title: 'Issuer placeholder',
    citation: DISCOVERY_VALIDATION,
    remediation: {
      rp: 'Use the discovery URL for your own tenant. If you must use the shared one, fill in the tenant ID from the token before comparing issuers.',
    },
    run: onDiscovery((doc, evidence) => {
      if (typeof doc.issuer !== 'string') return undefined;
      return /[{}]/.test(doc.issuer)
        ? {
            severity: 'warn',
            detail: `The issuer is ${doc.issuer}, which contains a placeholder instead of a real value. Shared multi-tenant endpoints such as Entra ID "common" do this. Real tokens carry the actual tenant ID, so a normal issuer comparison fails.`,
            evidence,
            pointer: '/issuer',
          }
        : {
            severity: 'pass',
            detail: 'The issuer is a real URL with no placeholder.',
            evidence,
            pointer: '/issuer',
          };
    }),
  },
  {
    id: 'oidc.discovery.issuer-form',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Issuer URL format',
    citation: DISCOVERY,
    remediation: { op: 'Use an https issuer with no query string and no fragment.' },
    run: onDiscovery((doc, evidence) => {
      if (typeof doc.issuer !== 'string') return undefined;
      let url: URL;
      try {
        url = new URL(doc.issuer);
      } catch {
        return {
          severity: 'error',
          detail: `issuer "${doc.issuer}" is not a URL.`,
          evidence,
          pointer: '/issuer',
        };
      }
      const faults = [
        url.protocol !== 'https:' && `scheme is ${url.protocol.slice(0, -1)}`,
        url.search && 'it has a query component',
        url.hash && 'it has a fragment',
      ].filter(Boolean);
      return faults.length
        ? {
            severity: 'error',
            detail: `The issuer URL is not valid: ${faults.join(', ')}.`,
            evidence,
            pointer: '/issuer',
          }
        : {
            severity: 'pass',
            detail: 'The issuer is an https URL with no query string or fragment.',
            evidence,
            pointer: '/issuer',
          };
    }),
  },
  {
    id: 'oidc.discovery.required-metadata',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Required fields',
    citation: DISCOVERY,
    remediation: { op: 'Add the missing fields to the discovery document.' },
    run: onDiscovery((doc, evidence) => {
      const required = [
        'issuer',
        'authorization_endpoint',
        'jwks_uri',
        'response_types_supported',
        'subject_types_supported',
        'id_token_signing_alg_values_supported',
      ];
      // token_endpoint is required unless only the implicit flow is offered.
      const implicitOnly =
        strings(doc.response_types_supported).length > 0 &&
        strings(doc.response_types_supported).every((t) => !t.split(' ').includes('code'));
      if (!implicitOnly) required.push('token_endpoint');
      const missing = required.filter((key) => doc[key] === undefined);
      return missing.length
        ? {
            severity: 'error',
            detail: `These required fields are missing: ${missing.join(', ')}.`,
            evidence,
          }
        : {
            severity: 'pass',
            detail: `All ${required.length} required fields are present.`,
            evidence,
          };
    }),
  },
  {
    id: 'oidc.discovery.endpoints-https',
    protocol: 'oidc',
    category: 'security',
    title: 'HTTPS on endpoints',
    citation: DISCOVERY,
    remediation: { op: 'Serve every endpoint over TLS.' },
    run: onDiscovery((doc, evidence) => {
      const present = ENDPOINT_FIELDS.filter((key) => doc[key] !== undefined);
      const bad = present.filter((key) => !isHttps(doc[key]));
      return bad.length
        ? {
            severity: 'error',
            detail: `Not https: ${bad.map((key) => `${key} (${String(doc[key])})`).join(', ')}.`,
            evidence,
            pointer: `/${bad[0]}`,
          }
        : {
            severity: 'pass',
            detail: `All ${present.length} advertised endpoints are https.`,
            evidence,
          };
    }),
  },
  {
    id: 'oidc.discovery.endpoint-origins',
    protocol: 'oidc',
    category: 'interop',
    title: 'Endpoint hosts',
    citation: DISCOVERY,
    remediation: {
      rp: 'If your network restricts outbound traffic, allow every host listed here, not only the issuer host.',
    },
    run: onDiscovery((doc, evidence) => {
      if (typeof doc.issuer !== 'string' || !URL.canParse(doc.issuer)) return undefined;
      const home = new URL(doc.issuer).origin;
      const foreign = new Set<string>();
      for (const key of ENDPOINT_FIELDS) {
        const value = doc[key];
        if (typeof value === 'string' && URL.canParse(value) && new URL(value).origin !== home) {
          foreign.add(`${key} on ${new URL(value).origin}`);
        }
      }
      return foreign.size
        ? {
            severity: 'info',
            detail: `Some endpoints are on a different host than the issuer (${home}): ${[...foreign].join(', ')}.`,
            evidence,
          }
        : { severity: 'pass', detail: `Every endpoint is on ${home}.`, evidence };
    }),
  },
  {
    id: 'oidc.discovery.code-flow',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Authorization code flow',
    citation: DISCOVERY,
    remediation: { op: 'Advertise "code" in response_types_supported.' },
    run: onDiscovery((doc, evidence) => {
      const types = strings(doc.response_types_supported);
      if (!types.length) return undefined;
      return types.includes('code')
        ? {
            severity: 'pass',
            detail: 'response_types_supported includes "code".',
            evidence,
            pointer: '/response_types_supported',
          }
        : {
            severity: 'error',
            detail: `response_types_supported is [${types.join(', ')}] and lacks "code".`,
            evidence,
            pointer: '/response_types_supported',
          };
    }),
  },
  {
    id: 'oidc.discovery.implicit-advertised',
    protocol: 'oidc',
    category: 'security',
    title: 'Implicit flow',
    citation: BCP('2.1.2'),
    remediation: {
      op: 'Stop offering response types that include "token".',
      rp: 'Use response_type=code with PKCE, whatever else is offered.',
    },
    run: onDiscovery((doc, evidence) => {
      const types = strings(doc.response_types_supported);
      if (!types.length) return undefined;
      const leaky = types.filter((t) => t.split(' ').includes('token'));
      return leaky.length
        ? {
            severity: 'warn',
            detail: `These response types return an access token in the browser redirect URL, where it can leak through history, logs, and referrers: ${leaky.join(', ')}.`,
            evidence,
            pointer: '/response_types_supported',
          }
        : {
            severity: 'pass',
            detail: 'No response type returns an access token through the browser.',
            evidence,
            pointer: '/response_types_supported',
          };
    }),
  },
  {
    id: 'oidc.discovery.password-grant',
    protocol: 'oidc',
    category: 'security',
    title: 'Password grant',
    citation: BCP('2.4'),
    remediation: { op: 'Remove "password" from grant_types_supported and disable it per client.' },
    run: onDiscovery((doc, evidence) => {
      // Absent means the default of authorization_code and implicit.
      const grants = strings(doc.grant_types_supported);
      return grants.includes('password')
        ? {
            severity: 'warn',
            detail:
              'The provider offers the "password" grant, where the app collects the password from the user directly. Current OAuth security guidance says not to use it.',
            evidence,
            pointer: '/grant_types_supported',
          }
        : {
            severity: 'pass',
            detail: 'The password grant is not advertised.',
            evidence,
            pointer: '/grant_types_supported',
          };
    }),
  },
  {
    id: 'oidc.discovery.pkce-s256',
    protocol: 'oidc',
    category: 'security',
    title: 'PKCE',
    citation: BCP('2.1.1'),
    remediation: {
      op: 'List "S256" in code_challenge_methods_supported.',
      rp: 'Send an S256 challenge anyway. Some providers support PKCE without listing it.',
    },
    run: onDiscovery((doc, evidence) => {
      const pointer = '/code_challenge_methods_supported';
      if (doc.code_challenge_methods_supported === undefined) {
        return {
          severity: 'warn',
          detail:
            'The provider does not list which PKCE methods it supports (code_challenge_methods_supported is missing). That is not proof PKCE is unsupported. This tool has not tested it.',
          evidence,
          pointer,
        };
      }
      const methods = strings(doc.code_challenge_methods_supported);
      if (!methods.includes('S256')) {
        return {
          severity: 'error',
          detail: `The provider lists only [${methods.join(', ')}] for PKCE. S256, the secure method, is missing.`,
          evidence,
          pointer,
        };
      }
      return methods.includes('plain')
        ? {
            severity: 'info',
            detail:
              'S256 is advertised, which is the secure PKCE method. The provider also accepts "plain", which sends the secret unhashed.',
            evidence,
            pointer,
            remediation: {
              op: 'Stop accepting "plain".',
              rp: 'Always send code_challenge_method=S256.',
            },
          }
        : { severity: 'pass', detail: 'S256 is advertised and "plain" is not.', evidence, pointer };
    }),
  },
  {
    id: 'oidc.discovery.rs256',
    protocol: 'oidc',
    category: 'conformance',
    title: 'RS256 signing',
    citation: DISCOVERY,
    remediation: { op: 'Include RS256 in id_token_signing_alg_values_supported.' },
    run: onDiscovery((doc, evidence) => {
      const algs = strings(doc.id_token_signing_alg_values_supported);
      if (!algs.length) return undefined;
      const pointer = '/id_token_signing_alg_values_supported';
      return algs.includes('RS256')
        ? { severity: 'pass', detail: `Signing algorithms: ${algs.join(', ')}.`, evidence, pointer }
        : {
            severity: 'warn',
            detail: `The provider signs ID tokens with [${algs.join(', ')}] only. The spec requires RS256 to be offered, and many libraries expect it by default.`,
            evidence,
            pointer,
          };
    }),
  },
  {
    id: 'oidc.discovery.alg-none',
    protocol: 'oidc',
    category: 'security',
    title: 'Unsigned ID tokens',
    citation: DISCOVERY,
    remediation: {
      op: 'Remove "none" from id_token_signing_alg_values_supported.',
      rp: 'Tell your library exactly which algorithms to accept, and never accept "none".',
    },
    run: onDiscovery((doc, evidence) => {
      const algs = strings(doc.id_token_signing_alg_values_supported);
      if (!algs.length) return undefined;
      const pointer = '/id_token_signing_alg_values_supported';
      return algs.includes('none')
        ? {
            severity: 'warn',
            detail:
              'The provider lists "none" as an ID token signing option, which means tokens with no signature at all.',
            evidence,
            pointer,
          }
        : { severity: 'pass', detail: '"none" is not advertised.', evidence, pointer };
    }),
  },
  {
    id: 'oidc.discovery.openid-scope',
    protocol: 'oidc',
    category: 'conformance',
    title: 'openid scope',
    citation: DISCOVERY,
    remediation: { op: 'Include "openid" in scopes_supported.' },
    run: onDiscovery((doc, evidence) => {
      if (doc.scopes_supported === undefined) return undefined;
      const scopes = strings(doc.scopes_supported);
      const pointer = '/scopes_supported';
      return scopes.includes('openid')
        ? { severity: 'pass', detail: `Scopes: ${scopes.join(', ')}.`, evidence, pointer }
        : {
            severity: 'warn',
            detail: `scopes_supported is [${scopes.join(', ')}] and omits "openid".`,
            evidence,
            pointer,
          };
    }),
  },
  {
    id: 'oidc.discovery.iss-parameter',
    protocol: 'oidc',
    category: 'security',
    title: 'Issuer in the login response',
    citation: {
      label: 'RFC 9207 (Authorization Server Issuer Identification), section 3',
      url: 'https://www.rfc-editor.org/rfc/rfc9207#section-3',
    },
    remediation: {
      op: 'Return "iss" in the login redirect and set authorization_response_iss_parameter_supported to true.',
      rp: 'If your app supports more than one provider, give each one its own redirect URI so responses cannot be confused. With a single provider this does not affect you.',
    },
    run: onDiscovery((doc, evidence) =>
      doc.authorization_response_iss_parameter_supported === true
        ? {
            severity: 'pass',
            detail:
              'The provider returns its issuer in the login redirect, so an app can confirm which provider answered.',
            evidence,
          }
        : {
            severity: 'info',
            detail:
              'The provider does not say it returns its issuer ("iss") in the login redirect. An app that supports several providers uses that value to confirm which provider a response came from. Without it, one provider could pass its response off as coming from another (a "mix-up" attack).',
            evidence,
          },
    ),
  },
  {
    id: 'oidc.jwks.reachable',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Signing keys URL',
    citation: DISCOVERY,
    remediation: { op: 'Serve the JWK Set at jwks_uri with a 200 and no authentication.' },
    run: reachable('oidc.jwks', 'The key set'),
  },
  {
    id: 'oidc.jwks.signing-keys',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Signing keys',
    citation: JWK('5'),
    remediation: { op: 'Publish at least one public key usable for signature verification.' },
    run: onJwks((keys, evidence) => {
      const signing = keys.filter((key) => key.use === undefined || key.use === 'sig');
      return signing.length
        ? {
            severity: 'pass',
            detail: `${signing.length} of ${keys.length} keys are usable for signatures.`,
            evidence,
            pointer: '/keys',
          }
        : {
            severity: 'error',
            detail: `The set holds ${keys.length} keys and none is usable for signatures.`,
            evidence,
            pointer: '/keys',
          };
    }),
  },
  {
    id: 'oidc.jwks.private-material',
    protocol: 'oidc',
    category: 'security',
    title: 'Private key exposure',
    citation: JWA('6'),
    remediation: { op: 'Rotate the affected keys immediately and publish public parameters only.' },
    run: onJwks((keys, evidence) => {
      const leaks = keys.flatMap((key, i) =>
        (key.kty === 'oct' && key.k !== undefined) ||
        ['d', 'p', 'q', 'dp', 'dq', 'qi'].some((p) => key[p] !== undefined)
          ? [keyLabel(key, i)]
          : [],
      );
      return leaks.length
        ? {
            severity: 'error',
            detail: `The key set includes private key material for ${leaks.join(', ')}. Anyone can use it to forge tokens.`,
            evidence,
            pointer: '/keys',
          }
        : {
            severity: 'pass',
            detail: 'Only public parameters are published.',
            evidence,
            pointer: '/keys',
          };
    }),
  },
  {
    id: 'oidc.jwks.kid-missing',
    protocol: 'oidc',
    category: 'interop',
    title: 'Key IDs',
    citation: JWK('4.5'),
    remediation: { op: 'Give every key a unique kid and set it in the JWS header.' },
    run: onJwks((keys, evidence) => {
      if (keys.length < 2) return undefined;
      const anonymous = keys.filter((key) => typeof key.kid !== 'string').length;
      return anonymous
        ? {
            severity: 'warn',
            detail: `${anonymous} of ${keys.length} keys have no key ID ("kid"). Apps then have to try every key to find the right one, which breaks easily when keys are rotated.`,
            evidence,
            pointer: '/keys',
          }
        : {
            severity: 'pass',
            detail: `All ${keys.length} keys carry a kid.`,
            evidence,
            pointer: '/keys',
          };
    }),
  },
  {
    id: 'oidc.jwks.kid-duplicate',
    protocol: 'oidc',
    category: 'interop',
    title: 'Duplicate key IDs',
    citation: JWK('4.5'),
    remediation: { op: 'Use a distinct kid for every key.' },
    run: onJwks((keys, evidence) => {
      const seen = new Map<string, number>();
      for (const key of keys) {
        if (typeof key.kid !== 'string') continue;
        // Distinct kty values may legitimately share a kid.
        const id = `${String(key.kty)} ${key.kid}`;
        seen.set(id, (seen.get(id) ?? 0) + 1);
      }
      const dupes = [...seen].filter(([, n]) => n > 1).map(([id]) => id);
      if (!seen.size) return undefined;
      return dupes.length
        ? {
            severity: 'error',
            detail: `These key IDs are used by more than one key: ${dupes.join('; ')}. Apps cannot tell which key to use.`,
            evidence,
            pointer: '/keys',
          }
        : { severity: 'pass', detail: 'No kid is reused.', evidence, pointer: '/keys' };
    }),
  },
  {
    id: 'oidc.jwks.rsa-key-size',
    protocol: 'oidc',
    category: 'security',
    title: 'RSA key size',
    citation: JWA('3.3'),
    remediation: { op: 'Rotate to RSA keys of 2048 bits or more.' },
    run: onJwks((keys, evidence) => {
      const sizes = keys.flatMap((key, i) => {
        if (key.kty !== 'RSA' || typeof key.n !== 'string') return [];
        try {
          const n = decodeBase64(key.n.replace(/-/g, '+').replace(/_/g, '/'));
          return [{ label: keyLabel(key, i), bits: integerBits(n) }];
        } catch {
          return [{ label: keyLabel(key, i), bits: 0 }];
        }
      });
      if (!sizes.length) return undefined;
      const weak = sizes.filter((s) => s.bits < 2048);
      return weak.length
        ? {
            severity: 'error',
            detail: `Undersized RSA keys: ${weak.map((s) => `${s.label} (${s.bits} bits)`).join(', ')}.`,
            evidence,
            pointer: '/keys',
          }
        : {
            severity: 'pass',
            detail: `RSA key sizes: ${sizes.map((s) => s.bits).join(', ')} bits.`,
            evidence,
            pointer: '/keys',
          };
    }),
  },
  {
    id: 'oidc.jwks.alg-coverage',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Keys for each signing algorithm',
    citation: DISCOVERY,
    remediation: {
      op: 'Publish a key for each advertised asymmetric algorithm, or stop advertising the algorithm.',
    },
    run: (ctx) => {
      const discovery = find(ctx, 'oidc.discovery');
      const jwks = find(ctx, 'oidc.jwks');
      const doc = discovery && json(discovery);
      const set = jwks && json(jwks);
      if (!doc || !jwks || !set) return undefined;
      const families = new Set(objects(set.keys).map((key) => String(key.kty)));
      const orphans = strings(doc.id_token_signing_alg_values_supported).filter((alg) => {
        const family = algFamily(alg);
        // Symmetric algorithms use the client secret, so no published key is expected.
        return family !== undefined && family !== 'oct' && !families.has(family);
      });
      return orphans.length
        ? {
            severity: 'warn',
            detail: `The provider says it signs with ${orphans.join(', ')}, but publishes no key of the matching type, so those tokens could not be verified. Key types published: ${[...families].join(', ') || 'none'}.`,
            evidence: jwks,
            pointer: '/keys',
          }
        : {
            severity: 'pass',
            detail: 'Every signing algorithm the provider lists has a matching published key.',
            evidence: jwks,
            pointer: '/keys',
          };
    },
  },
  {
    id: 'oidc.jwks.x5c-validity',
    protocol: 'oidc',
    category: 'interop',
    title: 'Certificates attached to keys',
    citation: JWK('4.7'),
    remediation: {
      op: 'Rotate keys before their certificate lapses, or drop x5c if the certificate is not meant to be validated.',
      rp: 'Apps that validate the attached certificate will fail. Apps that only use the raw key will keep working.',
    },
    run: onJwks((keys, evidence, ctx) => {
      const lapsed: string[] = [];
      let seen = 0;
      keys.forEach((key, i) => {
        const [leaf] = strings(key.x5c);
        if (!leaf) return;
        seen++;
        try {
          const cert = parseCertificate(leaf);
          if (ctx.instant > cert.notAfter)
            lapsed.push(`${keyLabel(key, i)} expired ${cert.notAfter.toISOString()}`);
          else if (ctx.instant < cert.notBefore)
            lapsed.push(`${keyLabel(key, i)} not valid until ${cert.notBefore.toISOString()}`);
        } catch {
          lapsed.push(`${keyLabel(key, i)} has an unreadable certificate`);
        }
      });
      if (!seen) return undefined;
      return lapsed.length
        ? { severity: 'warn', detail: `${lapsed.join('; ')}.`, evidence, pointer: '/keys' }
        : {
            severity: 'pass',
            detail: `${seen} attached certificates are valid at the evaluation instant.`,
            evidence,
            pointer: '/keys',
          };
    }),
  },
];
