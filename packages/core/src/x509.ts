// Minimal X.509 reader: just the fields the checks judge. Not a validator.

export interface Certificate {
  subject: string;
  notBefore: Date;
  notAfter: Date;
  signatureAlgorithm: string;
  keyType: 'RSA' | 'EC' | 'other';
  /** Modulus length for RSA, undefined otherwise. */
  keyBits?: number;
  selfSigned: boolean;
  /** The SubjectPublicKeyInfo as DER, which is what a signature is verified with. */
  spki: Uint8Array<ArrayBuffer>;
  /** The named curve of an EC key, in WebCrypto's spelling. */
  curve?: string;
}

const OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.2.1': 'ecPublicKey',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'Ed25519',
};

const CURVES: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
};

interface Tlv {
  tag: number;
  /** Where the element begins, header included. */
  at: number;
  /** Where its content begins. */
  start: number;
  end: number;
}

function read(der: Uint8Array, offset: number): Tlv {
  const tag = der[offset];
  let length = der[offset + 1];
  if (tag === undefined || length === undefined) throw new Error('truncated DER');
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('unsupported DER length');
    length = 0;
    for (let i = 0; i < count; i++) {
      const byte = der[start + i];
      if (byte === undefined) throw new Error('truncated DER');
      length = length * 256 + byte;
    }
    start += count;
  }
  const end = start + length;
  if (end > der.length) throw new Error('truncated DER');
  return { tag, at: offset, start, end };
}

function children(der: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let at = parent.start; at < parent.end; ) {
    const tlv = read(der, at);
    out.push(tlv);
    at = tlv.end;
  }
  return out;
}

function oid(der: Uint8Array, tlv: Tlv): string {
  const bytes = der.subarray(tlv.start, tlv.end);
  const first = bytes[0] ?? 0;
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function time(der: Uint8Array, tlv: Tlv): Date {
  const text = new TextDecoder().decode(der.subarray(tlv.start, tlv.end));
  // UTCTime carries a two digit year, pivoting at 1950 (RFC 5280 4.1.2.5.1).
  const full = tlv.tag === 0x17 ? (Number(text.slice(0, 2)) >= 50 ? '19' : '20') + text : text;
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(full);
  if (!m) throw new Error(`unreadable certificate time: ${text}`);
  const [year, month, day, hour, minute, second] = m.slice(1).map((part) => Number(part ?? 0));
  return new Date(Date.UTC(year ?? 0, (month ?? 1) - 1, day, hour, minute, second));
}

function commonName(der: Uint8Array, name: Tlv): string {
  const parts: string[] = [];
  for (const set of children(der, name)) {
    for (const attr of children(der, set)) {
      const [type, value] = children(der, attr);
      if (!type || !value) continue;
      const text = new TextDecoder().decode(der.subarray(value.start, value.end));
      if (oid(der, type) === '2.5.4.3') return text;
      parts.push(text);
    }
  }
  return parts.join(', ');
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export function decodeBase64(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function parseCertificate(base64: string): Certificate {
  const der = decodeBase64(base64);
  const [tbs, outerAlg] = children(der, read(der, 0));
  if (!tbs || !outerAlg) throw new Error('not a certificate');
  const fields = children(der, tbs);
  // The version is an optional explicit [0], so skip it when present.
  const base = fields[0]?.tag === 0xa0 ? 1 : 0;
  const issuer = fields[base + 2];
  const validity = fields[base + 3];
  const subject = fields[base + 4];
  const spki = fields[base + 5];
  if (!issuer || !validity || !subject || !spki) throw new Error('not a certificate');

  const [notBefore, notAfter] = children(der, validity);
  const [keyAlg, keyBits] = children(der, spki);
  const [sigOid] = children(der, outerAlg);
  const [keyOid] = keyAlg ? children(der, keyAlg) : [];
  if (!notBefore || !notAfter || !keyBits || !sigOid || !keyOid)
    throw new Error('not a certificate');

  const keyAlgName = OIDS[oid(der, keyOid)];
  const cert: Certificate = {
    subject: commonName(der, subject),
    notBefore: time(der, notBefore),
    notAfter: time(der, notAfter),
    signatureAlgorithm: OIDS[oid(der, sigOid)] ?? oid(der, sigOid),
    keyType: keyAlgName === 'rsaEncryption' ? 'RSA' : keyAlgName === 'ecPublicKey' ? 'EC' : 'other',
    selfSigned: equal(
      der.subarray(issuer.start, issuer.end),
      der.subarray(subject.start, subject.end),
    ),
    spki: der.slice(spki.at, spki.end),
  };
  const [, curveOid] = keyAlg ? children(der, keyAlg) : [];
  const curve =
    cert.keyType === 'EC' && curveOid?.tag === 0x06 ? CURVES[oid(der, curveOid)] : undefined;
  if (curve) cert.curve = curve;
  if (cert.keyType === 'RSA') {
    // BIT STRING: one unused-bits byte, then RSAPublicKey ::= SEQUENCE { modulus, exponent }.
    const [modulus] = children(der, read(der, keyBits.start + 1));
    if (modulus) cert.keyBits = integerBits(der.subarray(modulus.start, modulus.end));
  }
  return cert;
}

/** Bit length of a big-endian unsigned integer, ignoring leading zeros. */
export function integerBits(bytes: Uint8Array): number {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  const top = bytes[i];
  if (top === undefined) return 0;
  return (bytes.length - i - 1) * 8 + (32 - Math.clz32(top));
}
