import { fits, type Jwt, jwt, verifiable, verify } from '../jwt.js';
import type { Check, CheckContext, Citation, Evidence, Outcome } from '../model.js';
import { type Json, json, objects, strings } from '../parse.js';

const CORE = (anchor: string, section: string): Citation => ({
  label: `OpenID Connect Core 1.0, section ${section}`,
  url: `https://openid.net/specs/openid-connect-core-1_0.html#${anchor}`,
});
const ID_TOKEN = CORE('IDToken', '2');
const VALIDATION = CORE('IDTokenValidation', '3.1.3.7');
const JWS: Citation = {
  label: 'RFC 7515 (JSON Web Signature), section 5.2',
  url: 'https://www.rfc-editor.org/rfc/rfc7515#section-5.2',
};
const JWS_KID: Citation = {
  label: 'RFC 7515 (JSON Web Signature), section 4.1.4',
  url: 'https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4',
};
const JWT_FORMAT: Citation = {
  label: 'RFC 7519 (JSON Web Token), section 7.2',
  url: 'https://www.rfc-editor.org/rfc/rfc7519#section-7.2',
};
const JWT_BCP: Citation = {
  label: 'RFC 8725 (JSON Web Token BCP), section 3.1',
  url: 'https://www.rfc-editor.org/rfc/rfc8725#section-3.1',
};

const AUDIENCE_ADVICE =
  'Accept the token only if "aud" contains your client ID, and if "azp" is present only if it is your client ID.';

type Result = Outcome | Outcome[] | undefined;

const find = (ctx: CheckContext, kind: Evidence['kind']) =>
  ctx.workspace.evidence.find((e) => e.kind === kind);

/** Runs a check body against the pasted token, when there is one and it decodes. */
function onToken<R extends Result | Promise<Result>>(
  body: (token: Jwt, evidence: Evidence, ctx: CheckContext) => R,
): (ctx: CheckContext) => R | undefined {
  return (ctx) => {
    const evidence = find(ctx, 'oidc.id-token');
    const token = evidence && jwt(evidence).jwt;
    return evidence && token ? body(token, evidence, ctx) : undefined;
  };
}

function publishedKeys(ctx: CheckContext): Json[] | undefined {
  const evidence = find(ctx, 'oidc.jwks');
  const doc = evidence && json(evidence);
  return doc ? objects(doc.keys) : undefined;
}

const name = (key: Json) =>
  typeof key.kid === 'string' ? `kid "${key.kid}"` : 'a key with no kid';

/** The keys a relying party would try: the one the header names, else every key that fits. */
function candidates(token: Jwt, keys: Json[]): Json[] {
  const { alg, kid } = token.header;
  if (typeof alg !== 'string') return [];
  const fitting = keys.filter((key) => fits(key, alg));
  const named = typeof kid === 'string' ? fitting.filter((key) => key.kid === kid) : [];
  return named.length ? named : fitting;
}

const UNITS: Array<[number, string]> = [
  [86_400, 'day'],
  [3_600, 'hour'],
  [60, 'minute'],
  [1, 'second'],
];

function span(seconds: number): string {
  const size = Math.abs(seconds);
  const [unit, label] = UNITS.find(([length]) => size >= length) ?? [1, 'second'];
  const count = Math.floor(size / unit);
  return `${count} ${label}${count === 1 ? '' : 's'}`;
}

const at = (seconds: number) => new Date(seconds * 1000).toISOString();

export const idTokenChecks: Check[] = [
  {
    id: 'oidc.id-token.format',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Token structure',
    citation: JWT_FORMAT,
    remediation: {
      rp: 'Paste the complete token as it was received: three parts separated by dots.',
    },
    run(ctx) {
      const evidence = find(ctx, 'oidc.id-token');
      if (!evidence) return undefined;
      const { error } = jwt(evidence);
      return error
        ? { severity: 'error', detail: `The token cannot be read: ${error}.`, evidence }
        : {
            severity: 'pass',
            detail: 'The token has a header, a payload, and a signature, and both decode to JSON.',
            evidence,
          };
    },
  },
  {
    id: 'oidc.id-token.alg',
    protocol: 'oidc',
    category: 'security',
    title: 'Signing algorithm',
    citation: JWT_BCP,
    remediation: {
      op: 'Sign ID tokens with an asymmetric algorithm that the discovery document advertises.',
      rp: 'Accept only the algorithms you expect, and never accept "none".',
    },
    run: onToken((token, evidence, ctx) => {
      const { alg } = token.header;
      const pointer = '/header/alg';
      if (typeof alg !== 'string') {
        return {
          severity: 'error',
          detail: 'The header has no "alg", so nothing says how the token was signed.',
          evidence,
          pointer,
        };
      }
      if (alg.toLowerCase() === 'none') {
        return {
          severity: 'error',
          detail: 'The token is unsigned ("alg" is "none"). Anyone can write a token like this.',
          evidence,
          pointer,
        };
      }
      const discovery = find(ctx, 'oidc.discovery');
      const advertised = strings(
        (discovery && json(discovery))?.id_token_signing_alg_values_supported,
      );
      if (advertised.length && !advertised.includes(alg)) {
        return {
          severity: 'error',
          detail: `The token is signed with ${alg}, which the provider does not advertise for ID tokens (${advertised.join(', ')}).`,
          evidence,
          pointer,
        };
      }
      if (/^HS\d+$/.test(alg)) {
        return {
          severity: 'warn',
          detail: `The token is signed with ${alg}, a shared-secret algorithm. Everyone who holds the client secret can write tokens like this one, and it cannot be verified from published keys.`,
          evidence,
          pointer,
        };
      }
      return {
        severity: 'pass',
        detail: advertised.length
          ? `The token is signed with ${alg}, which the provider advertises.`
          : `The token is signed with ${alg}.`,
        evidence,
        pointer,
      };
    }),
  },
  {
    id: 'oidc.id-token.key',
    protocol: 'oidc',
    category: 'interop',
    title: 'Signing key',
    citation: JWS_KID,
    remediation: {
      op: 'Put the "kid" of the signing key in the token header, and keep a key published for as long as tokens signed with it are valid.',
      rp: 'Fetch the key set again when a "kid" is unknown, and confirm the token came from the issuer and tenant you inspected.',
    },
    run: onToken((token, evidence, ctx) => {
      const { alg, kid } = token.header;
      const keys = publishedKeys(ctx);
      if (typeof alg !== 'string' || !verifiable(alg) || !keys) return undefined;
      const pointer = '/header/kid';
      const fitting = keys.filter((key) => fits(key, alg));
      if (typeof kid !== 'string') {
        if (fitting.length === 1) {
          return {
            severity: 'info',
            detail: `The header names no "kid". Only one published key fits ${alg}, so there is nothing to confuse it with yet.`,
            evidence,
            pointer,
          };
        }
        return {
          severity: fitting.length ? 'warn' : 'error',
          detail: fitting.length
            ? `The header names no "kid" and ${fitting.length} published keys fit ${alg}, so a client has to try each one.`
            : `The header names no "kid" and no published key fits ${alg}.`,
          evidence,
          pointer,
        };
      }
      if (fitting.some((key) => key.kid === kid)) {
        return {
          severity: 'pass',
          detail: `The header names kid "${kid}", which the provider publishes.`,
          evidence,
          pointer,
        };
      }
      const known = keys.flatMap((key) => (typeof key.kid === 'string' ? [key.kid] : []));
      return {
        severity: 'error',
        detail: keys.some((key) => key.kid === kid)
          ? `The header names kid "${kid}", but that published key cannot sign with ${alg}.`
          : `The header names kid "${kid}", which the provider does not publish (it publishes ${known.join(', ') || 'no named keys'}). The key may have been rotated out, or the token is from another issuer or tenant.`,
        evidence,
        pointer,
      };
    }),
  },
  {
    id: 'oidc.id-token.signature',
    protocol: 'oidc',
    category: 'security',
    title: 'Signature',
    citation: JWS,
    remediation: {
      op: 'Confirm the published key set contains the key that signs ID tokens.',
      rp: 'Reject this token. Confirm it was copied whole and that it came from the issuer you inspected.',
    },
    run: onToken(async (token, evidence, ctx): Promise<Result> => {
      const { alg } = token.header;
      if (typeof alg !== 'string') return undefined;
      const skipped = (why: string): Outcome => ({
        severity: 'info',
        detail: `The signature was not verified: ${why}`,
        evidence,
        // Nothing was found wrong, so there is nothing to tell either side to change.
        remediation: {},
      });
      if (alg.toLowerCase() === 'none') return skipped('the token carries none.');
      if (/^HS\d+$/.test(alg)) {
        return skipped(`${alg} needs the client secret, which this tool never asks for.`);
      }
      if (!verifiable(alg)) return skipped(`${alg} is not an algorithm this tool can check.`);
      const keys = publishedKeys(ctx);
      if (!keys) return skipped('no key set could be read from the issuer.');
      const tried = candidates(token, keys);
      if (!tried.length) return skipped(`no published key fits ${alg}.`);

      let unusable = 0;
      for (const key of tried) {
        const verdict = await verify(token, alg, key);
        if (verdict === 'valid') {
          return {
            severity: 'pass',
            detail: `The signature verifies with ${alg} against ${name(key)} from the published key set.`,
            evidence,
          };
        }
        if (verdict === 'unusable') unusable++;
      }
      if (unusable === tried.length) {
        return skipped(`the published ${tried.length === 1 ? 'key' : 'keys'} could not be loaded.`);
      }
      return {
        severity: 'error',
        detail: `The signature does not verify with ${alg} against ${tried.map(name).join(', ')}. The token was altered, cut short, or signed by a different key.`,
        evidence,
      };
    }),
  },
  {
    id: 'oidc.id-token.issuer',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Issuer claim',
    citation: VALIDATION,
    remediation: {
      op: 'Put exactly the issuer from the discovery document in the "iss" claim.',
      rp: 'Compare "iss" with the discovery issuer character for character, and use the discovery URL of your own tenant.',
    },
    run: onToken((token, evidence, ctx) => {
      const discovery = find(ctx, 'oidc.discovery');
      const issuer = (discovery && json(discovery))?.issuer;
      const { iss } = token.claims;
      if (typeof iss !== 'string' || typeof issuer !== 'string') return undefined;
      const pointer = '/payload/iss';
      if (iss === issuer) {
        return {
          severity: 'pass',
          detail: `"iss" is ${iss}, exactly the issuer the provider publishes.`,
          evidence,
          pointer,
        };
      }
      const close = iss.replace(/\/$/, '') === issuer.replace(/\/$/, '');
      return {
        severity: 'error',
        detail: `"iss" is ${iss} but the provider publishes ${issuer}${close ? ', which differs only by a trailing slash' : ''}. A client that compares them exactly rejects this token.`,
        evidence,
        pointer,
      };
    }),
  },
  {
    id: 'oidc.id-token.required-claims',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Required claims',
    citation: ID_TOKEN,
    remediation: {
      op: 'Include "iss", "sub", "aud", "exp", and "iat" in every ID token, with times as numbers of seconds.',
      rp: 'If this is an access token rather than an ID token, these claims are not all required of it.',
    },
    run: onToken((token, evidence) => {
      const claims = token.claims;
      const text = (value: unknown) => typeof value === 'string' && value !== '';
      const problems = [
        ...(['iss', 'sub'] as const).flatMap((claim) =>
          text(claims[claim])
            ? []
            : [`"${claim}" is ${claim in claims ? 'not a string' : 'missing'}`],
        ),
        ...(text(claims.aud) ||
        (Array.isArray(claims.aud) && claims.aud.length && claims.aud.every(text))
          ? []
          : [`"aud" is ${'aud' in claims ? 'not a string or a list of strings' : 'missing'}`]),
        ...(['exp', 'iat'] as const).flatMap((claim) =>
          typeof claims[claim] === 'number'
            ? []
            : [`"${claim}" is ${claim in claims ? 'not a number' : 'missing'}`],
        ),
      ];
      return problems.length
        ? {
            severity: 'error',
            detail: `The token does not carry every claim an ID token must: ${problems.join(', ')}.`,
            evidence,
            pointer: '/payload',
          }
        : {
            severity: 'pass',
            detail: 'The token carries "iss", "sub", "aud", "exp", and "iat".',
            evidence,
            pointer: '/payload',
          };
    }),
  },
  {
    id: 'oidc.id-token.time',
    protocol: 'oidc',
    category: 'conformance',
    title: 'Validity period',
    citation: VALIDATION,
    remediation: {
      op: 'Check the clock on the signing servers.',
      rp: 'Reject a token outside its validity period. To judge a token as it was when it was issued, evaluate as of that moment.',
    },
    run: onToken((token, evidence, ctx) => {
      const { exp, iat, nbf } = token.claims;
      if (typeof exp !== 'number') return undefined;
      const now = ctx.instant.getTime() / 1000;
      if (typeof nbf === 'number' && nbf > now) {
        return {
          severity: 'error',
          detail: `The token is not valid until ${at(nbf)}, ${span(nbf - now)} after the evaluation instant.`,
          evidence,
          pointer: '/payload/nbf',
        };
      }
      if (now >= exp) {
        return {
          severity: 'warn',
          detail: `The token expired at ${at(exp)}, ${span(now - exp)} before the evaluation instant.`,
          evidence,
          pointer: '/payload/exp',
        };
      }
      // Five minutes is the clock difference most libraries tolerate.
      if (typeof iat === 'number' && iat > now + 300) {
        return {
          severity: 'warn',
          detail: `The token says it was issued at ${at(iat)}, ${span(iat - now)} after the evaluation instant. One of the two clocks is wrong.`,
          evidence,
          pointer: '/payload/iat',
        };
      }
      return {
        severity: 'pass',
        detail: `The token is within its validity period and expires at ${at(exp)}, in ${span(exp - now)}.`,
        evidence,
        pointer: '/payload/exp',
      };
    }),
  },
  {
    id: 'oidc.id-token.audience',
    protocol: 'oidc',
    category: 'security',
    title: 'Audience',
    citation: VALIDATION,
    remediation: {
      op: 'Add "azp" naming the client the token was issued to whenever "aud" lists more than one value.',
      rp: AUDIENCE_ADVICE,
    },
    run: onToken((token, evidence) => {
      const { aud, azp } = token.claims;
      const audiences = typeof aud === 'string' ? [aud] : strings(aud);
      if (!audiences.length) return undefined;
      const pointer = '/payload/aud';
      if (audiences.length > 1 && typeof azp !== 'string') {
        return {
          severity: 'warn',
          detail: `"aud" lists ${audiences.length} audiences (${audiences.join(', ')}) and there is no "azp" to say which client the token was issued to.`,
          evidence,
          pointer,
        };
      }
      return {
        severity: 'info',
        detail: `The token is addressed to ${audiences.join(', ')}${typeof azp === 'string' ? `, issued to ${azp}` : ''}. Only you can confirm that this is your client ID.`,
        evidence,
        pointer,
        remediation: {
          rp: AUDIENCE_ADVICE,
        },
      };
    }),
  },
];
