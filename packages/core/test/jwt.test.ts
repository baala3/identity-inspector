import { describe, expect, it } from 'vitest';
import { parseJwt, verify } from '../src/jwt.js';

const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const RSA = { modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };

// One row per family of algorithm the engine claims it can verify.
const ALGORITHMS: Array<[string, object, object]> = [
  ['RS256', { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', ...RSA }, { name: 'RSASSA-PKCS1-v1_5' }],
  ['PS384', { name: 'RSA-PSS', hash: 'SHA-384', ...RSA }, { name: 'RSA-PSS', saltLength: 48 }],
  ['ES256', { name: 'ECDSA', namedCurve: 'P-256' }, { name: 'ECDSA', hash: 'SHA-256' }],
  ['ES512', { name: 'ECDSA', namedCurve: 'P-521' }, { name: 'ECDSA', hash: 'SHA-512' }],
  ['EdDSA', { name: 'Ed25519' }, { name: 'Ed25519' }],
];

describe('verify', () => {
  it.each(ALGORITHMS)(
    'accepts a genuine %s signature and refuses an altered token',
    async (alg, generate, sign) => {
      const pair = (await crypto.subtle.generateKey(generate as RsaHashedKeyGenParams, true, [
        'sign',
        'verify',
      ])) as CryptoKeyPair;
      const published = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)) };
      const input = `${segment({ alg })}.${segment({ sub: 'user-1' })}`;
      const signature = Buffer.from(
        await crypto.subtle.sign(sign as AlgorithmIdentifier, pair.privateKey, Buffer.from(input)),
      ).toString('base64url');

      const genuine = parseJwt(`${input}.${signature}`).jwt;
      const altered = parseJwt(`${segment({ alg })}.${segment({ sub: 'admin' })}.${signature}`).jwt;
      if (!genuine || !altered) throw new Error('fixture tokens must parse');
      expect(await verify(genuine, alg, published)).toBe('valid');
      expect(await verify(altered, alg, published)).toBe('invalid');
    },
  );

  it('reports a key it cannot load instead of calling the signature wrong', async () => {
    const token = parseJwt(`${segment({ alg: 'RS256' })}.${segment({})}.c2ln`).jwt;
    if (!token) throw new Error('fixture token must parse');
    expect(await verify(token, 'RS256', { kty: 'RSA', n: 'AQAB' })).toBe('unusable');
    expect(await verify(token, 'ES256K', { kty: 'EC' })).toBe('unusable');
  });
});

describe('parseJwt', () => {
  it.each([
    ['https://op.example', /three base64url segments/],
    [`bm90.${segment({})}.c2ln`, /header does not decode/],
    [`${segment({})}.${segment([1])}.c2ln`, /payload does not decode/],
  ])('refuses %s', (text, why) => {
    expect(parseJwt(text).error).toMatch(why);
  });
});
