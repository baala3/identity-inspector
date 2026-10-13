import type { Evidence } from './model.js';
import type { Json } from './parse.js';

export interface Jwt {
  header: Json;
  claims: Json;
  /** The exact bytes the signature covers: the first two segments as pasted. */
  signingInput: string;
  signature: Uint8Array<ArrayBuffer>;
}

export type JwtResult = { jwt: Jwt; error?: undefined } | { jwt?: undefined; error: string };

const SIGNED = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
// Five parts is the encrypted form, which is recognised so it can be refused by name.
const ENCRYPTED = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*){4}$/;

/**
 * Base64url segments whose first is a JSON object: a token in compact form.
 * The shape alone is not enough, because a hostname such as accounts.google.com has it too.
 */
export function looksLikeJwt(input: string): boolean {
  const token = input.trim();
  return (
    (SIGNED.test(token) || ENCRYPTED.test(token)) &&
    object(token.slice(0, token.indexOf('.'))) !== undefined
  );
}

function bytes(segment: string): Uint8Array<ArrayBuffer> {
  const binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function object(segment: string): Json | undefined {
  try {
    const parsed: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(bytes(segment)),
    );
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Json)
      : undefined;
  } catch {
    return undefined;
  }
}

export function parseJwt(text: string): JwtResult {
  const token = text.trim();
  if (ENCRYPTED.test(token)) {
    return { error: 'it is encrypted (five parts), so only its recipient can read what it says' };
  }
  if (!SIGNED.test(token)) return { error: 'it is not three base64url segments joined by dots' };
  const [head = '', body = '', tail = ''] = token.split('.');
  const header = object(head);
  if (!header) return { error: 'the header does not decode to a JSON object' };
  const claims = object(body);
  if (!claims) return { error: 'the payload does not decode to a JSON object' };
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = bytes(tail);
  } catch {
    return { error: 'the signature is not valid base64url' };
  }
  return { jwt: { header, claims, signingInput: `${head}.${body}`, signature } };
}

export type TokenKind = 'id' | 'access';

export const KIND_LABEL: Record<TokenKind, string> = { id: 'ID token', access: 'access token' };

/**
 * Which kind of token this is, and what gave it away. Only "typ": "at+jwt" is a
 * declaration; the rest is inference from claims that one kind carries and the other does not.
 */
export function kindOf(token: Jwt): { kind: TokenKind; why: string; declared: boolean } {
  const { typ } = token.header;
  if (typeof typ === 'string' && typ.toLowerCase().replace(/^application\//, '') === 'at+jwt') {
    return { kind: 'access', why: 'its header declares "typ": "at+jwt"', declared: true };
  }
  for (const claim of ['nonce', 'at_hash', 'c_hash']) {
    if (claim in token.claims) {
      return {
        kind: 'id',
        why: `it carries "${claim}", which only an ID token has`,
        declared: false,
      };
    }
  }
  for (const claim of ['scope', 'scp']) {
    if (claim in token.claims) {
      return {
        kind: 'access',
        why: `it carries "${claim}", which an ID token does not`,
        declared: false,
      };
    }
  }
  return { kind: 'id', why: 'nothing in it marks it as an access token', declared: false };
}

const cache = new WeakMap<Evidence, JwtResult>();

export function jwt(evidence: Evidence): JwtResult {
  let result = cache.get(evidence);
  if (!result) {
    result = parseJwt(evidence.raw);
    cache.set(evidence, result);
  }
  return result;
}

interface Scheme {
  kty: string;
  crv?: string;
  key: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  verify: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
}

const CURVES: Record<string, string> = { '256': 'P-256', '384': 'P-384', '512': 'P-521' };

/** How WebCrypto verifies a JWS algorithm, or undefined when it cannot. */
function scheme(alg: string): Scheme | undefined {
  const match = /^(RS|PS|ES)(256|384|512)$/.exec(alg);
  if (match) {
    const [, family, bits = ''] = match;
    const hash = `SHA-${bits}`;
    if (family === 'RS') {
      const name = 'RSASSA-PKCS1-v1_5';
      return { kty: 'RSA', key: { name, hash }, verify: { name } };
    }
    if (family === 'PS') {
      const name = 'RSA-PSS';
      return { kty: 'RSA', key: { name, hash }, verify: { name, saltLength: Number(bits) / 8 } };
    }
    const namedCurve = CURVES[bits] ?? '';
    return {
      kty: 'EC',
      crv: namedCurve,
      key: { name: 'ECDSA', namedCurve },
      verify: { name: 'ECDSA', hash },
    };
  }
  if (alg === 'EdDSA') {
    return { kty: 'OKP', crv: 'Ed25519', key: { name: 'Ed25519' }, verify: { name: 'Ed25519' } };
  }
  return undefined;
}

export const verifiable = (alg: string) => scheme(alg) !== undefined;

/** Whether a published key could have produced a signature with this algorithm. */
export function fits(key: Json, alg: string): boolean {
  const need = scheme(alg);
  if (!need || key.kty !== need.kty) return false;
  if (need.crv && key.crv !== need.crv) return false;
  if (typeof key.use === 'string' && key.use !== 'sig') return false;
  return typeof key.alg !== 'string' || key.alg === alg;
}

export type Verdict = 'valid' | 'invalid' | 'unusable';

/** Checks the signature against one public key. Unusable means the key could not be loaded. */
export async function verify(token: Jwt, alg: string, key: Json): Promise<Verdict> {
  const how = scheme(alg);
  if (!how) return 'unusable';
  // Only the public members: "use", "alg", and "key_ops" would be judged by the importer too.
  const { kty, crv, n, e, x, y } = key as Record<string, string>;
  let imported: CryptoKey;
  try {
    imported = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(JSON.stringify({ kty, crv, n, e, x, y })),
      how.key,
      false,
      ['verify'],
    );
  } catch {
    return 'unusable';
  }
  const ok = await crypto.subtle.verify(
    how.verify,
    imported,
    token.signature,
    new TextEncoder().encode(token.signingInput),
  );
  return ok ? 'valid' : 'invalid';
}
