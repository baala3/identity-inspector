import { execFileSync } from 'node:child_process';
import { createSign } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignedXml } from 'xml-crypto';

export interface Identity {
  /** PEM private key. */
  key: string;
  /** Certificate body as base64, the form metadata and signatures carry. */
  cert: string;
}

const dir = mkdtempSync(join(tmpdir(), 'idi-saml-'));

/** A throwaway self-signed identity, made by openssl so no private key lives in the repository. */
export function identity(name: string, keyArgs: string[]): Identity {
  const key = join(dir, `${name}.key`);
  const cert = join(dir, `${name}.crt`);
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-nodes',
      '-days',
      '3650',
      '-subj',
      `/CN=${name}`,
      ...keyArgs,
      '-keyout',
      key,
      '-out',
      cert,
    ],
    { stdio: 'ignore' },
  );
  return {
    key: readFileSync(key, 'utf8'),
    cert: readFileSync(cert, 'utf8').replace(/-----[A-Z ]+-----|\s+/g, ''),
  };
}

const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

export interface SignOptions {
  /** Local name of the element to sign: Response or Assertion. */
  element: 'Response' | 'Assertion';
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
}

/**
 * Signs with xml-crypto, an implementation independent of the engine's own
 * canonicalizer, so agreement between the two means something.
 */
export function sign(xml: string, signer: Identity, options: SignOptions): string {
  const signed = new SignedXml({
    privateKey: signer.key,
    publicCert: `-----BEGIN CERTIFICATE-----\n${signer.cert}\n-----END CERTIFICATE-----`,
    signatureAlgorithm:
      options.signatureAlgorithm ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: EXC_C14N,
  });
  // xml-crypto has no ECDSA of its own; it still does the canonicalization and the digest.
  for (const bits of ['256', '384', '512']) {
    const name = `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha${bits}`;
    signed.SignatureAlgorithms[name] = class {
      getAlgorithmName = () => name;
      getSignature = (signedInfo: string, privateKey: string) =>
        createSign(`SHA${bits}`)
          .update(signedInfo)
          .sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }, 'base64');
      verifySignature = () => false;
    } as never;
  }
  const xpath = `//*[local-name(.)='${options.element}']`;
  signed.addReference({
    xpath,
    transforms: [ENVELOPED, EXC_C14N],
    digestAlgorithm: options.digestAlgorithm ?? 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  // SAML puts the signature right after the Issuer of the element it signs.
  signed.computeSignature(xml, {
    prefix: 'ds',
    location: { reference: `${xpath}/*[local-name(.)='Issuer']`, action: 'after' },
  });
  return signed.getSignedXml();
}

/** Minimal IdP metadata publishing one signing certificate. */
export const metadataFor = (signer: Identity, entityId = 'https://idp.example/metadata') =>
  `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${entityId}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${signer.cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;

/** An unsigned assertion that stays inside its validity period whenever the tests run. */
export const plainAssertion = (id: string, nameId: string) =>
  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example/metadata</saml:Issuer><saml:Subject><saml:NameID>${nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example/acs" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>`;

export const plainResponse = (assertions: string, extra = '') =>
  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example/metadata</saml:Issuer>${extra}<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertions}</samlp:Response>`;
