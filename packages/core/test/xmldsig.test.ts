import { describe, expect, it } from 'vitest';
import { parseXml } from '../src/parse.js';
import { certificate, signatureOf, verifySignature } from '../src/xmldsig.js';
import { identity, sign } from './support/saml.js';

const idp = identity('idp', ['-newkey', 'rsa:2048']);
const other = identity('other', ['-newkey', 'rsa:2048']);

const RESPONSE = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2027-06-01T00:00:00Z">
  <saml:Issuer>https://idp.example/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2027-06-01T00:00:00Z">
    <saml:Issuer>https://idp.example/metadata</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <saml:Attribute Name="role"><saml:AttributeValue xsi:type="xs:string">a &amp; b &lt;admin&gt;</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;

function signature(xml: string, element: 'Response' | 'Assertion') {
  const { document } = parseXml(xml);
  const root = document?.documentElement;
  const parent =
    element === 'Response'
      ? root
      : root && Array.from(root.getElementsByTagName('saml:Assertion'))[0];
  const found = parent && signatureOf(parent);
  if (!found) throw new Error('fixture has no signature');
  return found;
}

const cert = (base64: string) => {
  const parsed = certificate(base64);
  if (!parsed) throw new Error('fixture certificate must parse');
  return parsed;
};

describe('verifySignature', () => {
  it.each([
    [
      'Assertion',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      'http://www.w3.org/2001/04/xmlenc#sha256',
    ],
    [
      'Response',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
      'http://www.w3.org/2001/04/xmlenc#sha512',
    ],
    [
      'Assertion',
      'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
      'http://www.w3.org/2000/09/xmldsig#sha1',
    ],
  ] as const)(
    'agrees with an independent signer on a signed %s (%s)',
    async (element, signatureAlgorithm, digestAlgorithm) => {
      const signed = sign(RESPONSE, idp, { element, signatureAlgorithm, digestAlgorithm });
      const found = signature(signed, element);
      expect(found.malformed).toBeUndefined();
      expect(found.embedded).toBe(idp.cert);
      expect(await verifySignature(found, cert(idp.cert))).toEqual({ state: 'valid' });
      expect(await verifySignature(found, cert(other.cert))).toEqual({ state: 'wrong-key' });
    },
  );

  it.each([
    ['prime256v1', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'],
    ['secp384r1', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384'],
  ])('verifies an ECDSA signature on %s', async (curve, signatureAlgorithm) => {
    const ec = identity(`ec-${curve}`, ['-newkey', 'ec', '-pkeyopt', `ec_paramgen_curve:${curve}`]);
    const signed = sign(RESPONSE, ec, { element: 'Assertion', signatureAlgorithm });
    expect(await verifySignature(signature(signed, 'Assertion'), cert(ec.cert))).toEqual({
      state: 'valid',
    });
    expect(await verifySignature(signature(signed, 'Assertion'), cert(idp.cert))).toEqual({
      state: 'wrong-key',
    });
  });

  it('notices content changed after signing', async () => {
    const signed = sign(RESPONSE, idp, { element: 'Assertion' });
    const forged = signed.replace('user@example.com', 'admin@example.com');
    expect(await verifySignature(signature(forged, 'Assertion'), cert(idp.cert))).toEqual({
      state: 'altered',
    });
  });
});
