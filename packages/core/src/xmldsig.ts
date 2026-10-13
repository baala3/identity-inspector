import type { Document, Element } from '@xmldom/xmldom';
import { canonicalize } from './c14n.js';
import { childElements, descendants } from './parse.js';
import { type Certificate, decodeBase64, parseCertificate } from './x509.js';

export const DS = 'http://www.w3.org/2000/09/xmldsig#';
const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

const DIGESTS: Record<string, string> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': 'SHA-1',
  'http://www.w3.org/2001/04/xmlenc#sha256': 'SHA-256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384': 'SHA-384',
  'http://www.w3.org/2001/04/xmlenc#sha512': 'SHA-512',
};

const SIGNATURES: Record<string, { family: 'RSA' | 'EC'; hash: string }> = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': { family: 'RSA', hash: 'SHA-1' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': { family: 'RSA', hash: 'SHA-256' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': { family: 'RSA', hash: 'SHA-384' },
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': { family: 'RSA', hash: 'SHA-512' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256': { family: 'EC', hash: 'SHA-256' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384': { family: 'EC', hash: 'SHA-384' },
  'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512': { family: 'EC', hash: 'SHA-512' },
};

/** The last part of an algorithm URI, which is how people name it. */
export const shortAlgorithm = (uri: string) => uri.split(/[#/]/).pop() ?? uri;

export interface Signature {
  /** The element the signature sits in, which is the only thing it may vouch for. */
  parent: Element;
  node: Element;
  signatureMethod: string;
  digestMethod: string;
  /** The certificate carried inside the signature, base64, when there is one. */
  embedded?: string;
  /** Why the signature's shape cannot be trusted to cover its parent, when it cannot. */
  malformed?: string;
}

/** Every element carrying this ID, which must be exactly one for a reference to mean anything. */
function withId(document: Document, id: string): Element[] {
  return Array.from(document.getElementsByTagName('*')).filter(
    (element) => element.getAttribute('ID') === id,
  );
}

const algorithm = (parent: Element | undefined, name: string) =>
  (parent && childElements(parent, DS, name)[0]?.getAttribute('Algorithm')) ?? '';

/**
 * Reads the signature that is a direct child of this element, if it has one.
 * The shape is judged strictly, because a signature that verifies over some other
 * element is how signature wrapping works.
 */
export function signatureOf(parent: Element): Signature | undefined {
  const node = childElements(parent, DS, 'Signature')[0];
  if (!node) return undefined;
  const info = childElements(node, DS, 'SignedInfo')[0];
  const references = info ? childElements(info, DS, 'Reference') : [];
  const [reference] = references;
  const transforms = reference
    ? childElements(reference, DS, 'Transforms').flatMap((t) => childElements(t, DS, 'Transform'))
    : [];
  const signature: Signature = {
    parent,
    node,
    signatureMethod: algorithm(info, 'SignatureMethod'),
    digestMethod: algorithm(reference, 'DigestMethod'),
  };
  const embedded = descendants(node, DS, 'X509Certificate')[0]?.textContent?.replace(/\s+/g, '');
  if (embedded) signature.embedded = embedded;

  const id = parent.getAttribute('ID');
  const uri = reference?.getAttribute('URI');
  const document = parent.ownerDocument;
  const foreign = transforms
    .map((t) => t.getAttribute('Algorithm') ?? '')
    .filter((a) => a !== ENVELOPED && a !== EXC_C14N && a !== `${EXC_C14N}WithComments`);
  const problem = !info
    ? 'it has no SignedInfo'
    : references.length !== 1
      ? `it has ${references.length} references instead of one`
      : !id
        ? 'the element it sits in has no ID to refer to'
        : uri !== `#${id}`
          ? `it refers to "${uri ?? ''}" instead of the element it sits in ("#${id}")`
          : document && withId(document, id).length !== 1
            ? `${withId(document, id).length} elements share the ID "${id}", so the reference is ambiguous`
            : foreign.length
              ? `it uses a transform this tool does not allow (${foreign.map(shortAlgorithm).join(', ')})`
              : undefined;
  if (problem) signature.malformed = problem;
  return signature;
}

export type Verdict =
  | { state: 'valid' }
  /** The signed content is not what was signed. */
  | { state: 'altered' }
  /** The content matches, but this key did not sign it. */
  | { state: 'wrong-key' }
  | { state: 'unsupported'; why: string };

/** The InclusiveNamespaces prefix list of a transform or canonicalization method. */
function prefixes(method: Element | undefined): string[] {
  const list = method && descendants(method, EXC_C14N, 'InclusiveNamespaces')[0];
  return (list?.getAttribute('PrefixList') ?? '').split(/\s+/).filter(Boolean);
}

const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * Verifies a well-shaped signature against one certificate: first that the content
 * still has the digest that was signed, then that this key signed that digest.
 */
export async function verifySignature(
  signature: Signature,
  certificate: Certificate,
): Promise<Verdict> {
  const info = childElements(signature.node, DS, 'SignedInfo')[0];
  const reference = info && childElements(info, DS, 'Reference')[0];
  const value = childElements(signature.node, DS, 'SignatureValue')[0]?.textContent;
  const expected = reference && childElements(reference, DS, 'DigestValue')[0]?.textContent;
  if (!info || !reference || !value || !expected) {
    return { state: 'unsupported', why: 'the signature is missing its digest or its value' };
  }

  const c14n = childElements(info, DS, 'CanonicalizationMethod')[0];
  const c14nAlgorithm = c14n?.getAttribute('Algorithm') ?? '';
  if (!c14nAlgorithm.startsWith(EXC_C14N)) {
    return {
      state: 'unsupported',
      why: `it is canonicalized with ${shortAlgorithm(c14nAlgorithm) || 'an unnamed method'}, and this tool only implements exclusive canonicalization`,
    };
  }
  const digest = DIGESTS[signature.digestMethod];
  const method = SIGNATURES[signature.signatureMethod];
  if (!digest) {
    return {
      state: 'unsupported',
      why: `the digest ${shortAlgorithm(signature.digestMethod)} is not one this tool can compute`,
    };
  }
  if (!method) {
    return {
      state: 'unsupported',
      why: `the signature method ${shortAlgorithm(signature.signatureMethod)} is not one this tool can check`,
    };
  }
  if (certificate.keyType !== method.family || (method.family === 'EC' && !certificate.curve)) {
    return { state: 'wrong-key' };
  }

  const transform = childElements(reference, DS, 'Transforms')
    .flatMap((t) => childElements(t, DS, 'Transform'))
    .find((t) => (t.getAttribute('Algorithm') ?? '').startsWith(EXC_C14N));
  const content = canonicalize(signature.parent, {
    omit: signature.node,
    inclusive: prefixes(transform),
    comments: transform?.getAttribute('Algorithm')?.endsWith('WithComments') ?? false,
  });
  const encode = (text: string) => new TextEncoder().encode(text);
  const actual = new Uint8Array(await crypto.subtle.digest(digest, encode(content)));
  let wanted: Uint8Array;
  let signed: Uint8Array<ArrayBuffer>;
  try {
    wanted = decodeBase64(expected);
    signed = decodeBase64(value);
  } catch {
    return { state: 'unsupported', why: 'its digest or its value is not valid base64' };
  }
  if (!sameBytes(actual, wanted)) return { state: 'altered' };

  const signedInfo = canonicalize(info, {
    inclusive: prefixes(c14n),
    comments: c14nAlgorithm.endsWith('WithComments'),
  });
  try {
    const params =
      method.family === 'RSA'
        ? { name: 'RSASSA-PKCS1-v1_5', hash: method.hash }
        : { name: 'ECDSA', namedCurve: certificate.curve ?? '' };
    const key = await crypto.subtle.importKey('spki', certificate.spki, params, false, ['verify']);
    const ok = await crypto.subtle.verify(
      method.family === 'RSA' ? params : { name: 'ECDSA', hash: method.hash },
      key,
      signed,
      encode(signedInfo),
    );
    return ok ? { state: 'valid' } : { state: 'wrong-key' };
  } catch {
    return { state: 'wrong-key' };
  }
}

/** A certificate from base64 text, or nothing when it cannot be read. */
export function certificate(base64: string | undefined): Certificate | undefined {
  try {
    return base64 ? parseCertificate(base64) : undefined;
  } catch {
    return undefined;
  }
}
