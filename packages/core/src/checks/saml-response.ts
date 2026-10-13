import type { Element } from '@xmldom/xmldom';
import type { Check, CheckContext, Citation, Evidence, Outcome } from '../model.js';
import { childElements, descendants, xml } from '../parse.js';
import type { Certificate } from '../x509.js';
import {
  certificate,
  DS,
  type Signature,
  shortAlgorithm,
  signatureOf,
  type Verdict,
  verifySignature,
} from '../xmldsig.js';
import { MD } from './saml.js';

export const SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
export const SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

const CORE = (section: string): Citation => ({
  label: `SAML 2.0 Core, section ${section}`,
  url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
});
const PROFILES = (section: string): Citation => ({
  label: `SAML 2.0 Profiles, section ${section}`,
  url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf',
});

type Result = Outcome | Outcome[] | undefined;

export interface Message {
  evidence: Evidence;
  /** The Response, absent when a bare assertion was pasted. */
  response: Element | undefined;
  /** Assertions an SP would consume: direct children only, never ones nested deeper. */
  assertions: Element[];
  encrypted: Element[];
}

const is = (element: Element | null | undefined, ns: string, name: string) =>
  element?.namespaceURI === ns && element.localName === name;

/** The pasted message, when it parses and its root is a Response or an Assertion. */
export function message(evidence: Evidence | undefined): Message | undefined {
  const root = evidence && xml(evidence).document?.documentElement;
  if (!evidence || !root) return undefined;
  if (is(root, SAMLP, 'Response')) {
    return {
      evidence,
      response: root,
      assertions: childElements(root, SAML, 'Assertion'),
      encrypted: childElements(root, SAML, 'EncryptedAssertion'),
    };
  }
  if (is(root, SAML, 'Assertion')) {
    return { evidence, response: undefined, assertions: [root], encrypted: [] };
  }
  return undefined;
}

const find = (ctx: CheckContext, kind: Evidence['kind']) =>
  ctx.workspace.evidence.find((e) => e.kind === kind);

const text = (parent: Element | undefined, ns: string, name: string) =>
  (parent && childElements(parent, ns, name)[0]?.textContent?.trim()) || undefined;

/** Who the message says it is from: the assertion's issuer, else the response's. */
export const issuerOf = (m: Message) =>
  text(m.assertions[0], SAML, 'Issuer') ?? text(m.response, SAML, 'Issuer');

interface Publisher {
  entityId: string;
  certificates: Certificate[];
}

/** The IdP the supplied metadata describes: the entity the message names, else the first. */
function publisher(ctx: CheckContext, m: Message): Publisher | undefined {
  const evidence = find(ctx, 'saml.metadata');
  const document = evidence && xml(evidence).document;
  if (!document) return undefined;
  const entities = descendants(document, MD, 'EntityDescriptor');
  const entity = entities.find((e) => e.getAttribute('entityID') === issuerOf(m)) ?? entities[0];
  const idp = entity && childElements(entity, MD, 'IDPSSODescriptor')[0];
  if (!entity || !idp) return undefined;
  return {
    entityId: entity.getAttribute('entityID') ?? '',
    certificates: childElements(idp, MD, 'KeyDescriptor')
      .filter((key) => key.getAttribute('use') !== 'encryption')
      .flatMap((key) => descendants(key, DS, 'X509Certificate'))
      .flatMap((node) => certificate(node.textContent ?? '') ?? []),
  };
}

interface Checked {
  where: 'Response' | 'Assertion';
  signature: Signature;
  /** Absent when the signature's shape ruled out verifying it at all. */
  verdict?: Verdict;
  /** Whose certificate it verified against, when it verified. */
  key?: 'published' | 'embedded';
  certificate?: Certificate;
}

async function check(
  where: Checked['where'],
  signature: Signature,
  published: Certificate[],
): Promise<Checked> {
  if (signature.malformed) return { where, signature };
  let last: Verdict = { state: 'wrong-key' };
  for (const candidate of published) {
    last = await verifySignature(signature, candidate);
    if (last.state === 'valid') {
      return { where, signature, verdict: last, key: 'published', certificate: candidate };
    }
    // Neither depends on which key is tried, so there is no point in trying another.
    if (last.state !== 'wrong-key') return { where, signature, verdict: last };
  }
  const embedded = certificate(signature.embedded);
  if (embedded) {
    last = await verifySignature(signature, embedded);
    if (last.state === 'valid') {
      return { where, signature, verdict: last, key: 'embedded', certificate: embedded };
    }
  }
  return { where, signature, verdict: last };
}

const verified = new WeakMap<Evidence, Promise<Checked[]>>();

/** Every signature on the message, verified once however many checks ask. */
function signatures(ctx: CheckContext, m: Message): Promise<Checked[]> {
  let result = verified.get(m.evidence);
  if (!result) {
    const published = publisher(ctx, m)?.certificates ?? [];
    const found: Array<[Checked['where'], Signature | undefined]> = [
      ['Response', m.response && signatureOf(m.response)],
      ['Assertion', m.assertions[0] && signatureOf(m.assertions[0])],
    ];
    result = Promise.all(
      found.flatMap(([where, signature]) =>
        signature ? [check(where, signature, published)] : [],
      ),
    );
    verified.set(m.evidence, result);
  }
  return result;
}

function onMessage<R extends Result | Promise<Result>>(
  body: (m: Message, ctx: CheckContext) => R,
): (ctx: CheckContext) => R | undefined {
  return (ctx) => {
    const m = message(find(ctx, 'saml.response'));
    return m ? body(m, ctx) : undefined;
  };
}

/** Runs a check body against the first readable assertion. */
function onAssertion(
  body: (assertion: Element, m: Message, ctx: CheckContext) => Result,
): (ctx: CheckContext) => Result {
  return onMessage((m, ctx) => {
    const [assertion] = m.assertions;
    return assertion ? body(assertion, m, ctx) : undefined;
  });
}

const UNITS: Array<[number, string]> = [
  [86_400, 'day'],
  [3_600, 'hour'],
  [60, 'minute'],
  [1, 'second'],
];

function span(milliseconds: number): string {
  const size = Math.abs(milliseconds) / 1000;
  const [unit, label] = UNITS.find(([length]) => size >= length) ?? [1, 'second'];
  const count = Math.floor(size / unit);
  return `${count} ${label}${count === 1 ? '' : 's'}`;
}

const instant = (element: Element | undefined, attribute: string): Date | undefined => {
  const value = element?.getAttribute(attribute);
  const date = value ? new Date(value) : undefined;
  return date && !Number.isNaN(date.getTime()) ? date : undefined;
};

const subjectName = (c: Certificate | undefined) => (c ? `"${c.subject}"` : 'an unreadable one');

export const samlResponseChecks: Check[] = [
  {
    id: 'saml.response.well-formed',
    protocol: 'saml',
    category: 'conformance',
    title: 'Response structure',
    citation: CORE('3.2.2'),
    remediation: {
      sp: 'Paste the whole SAMLResponse, either as XML or as the base64 text the browser posted.',
    },
    run(ctx) {
      const evidence = find(ctx, 'saml.response');
      if (!evidence) return undefined;
      const parsed = xml(evidence);
      if (!parsed.document) {
        return { severity: 'error', detail: `The XML cannot be read: ${parsed.error}.`, evidence };
      }
      const m = message(evidence);
      const root = parsed.document.documentElement;
      if (!m) {
        return {
          severity: 'error',
          detail: `The root element is ${root?.tagName ?? 'missing'}, not a SAML 2.0 Response or Assertion.`,
          evidence,
        };
      }
      const version = root?.getAttribute('Version');
      if (version !== '2.0') {
        return {
          severity: 'error',
          detail: `The message declares version "${version ?? ''}" where SAML 2.0 requires "2.0".`,
          evidence,
          pointer: '/@Version',
        };
      }
      const count = m.assertions.length + m.encrypted.length;
      return {
        severity: 'pass',
        detail: m.response
          ? `A SAML 2.0 Response carrying ${count} ${count === 1 ? 'assertion' : 'assertions'}.`
          : 'A SAML 2.0 Assertion on its own, without the Response it was sent in.',
        evidence,
      };
    },
  },
  {
    id: 'saml.response.status',
    protocol: 'saml',
    category: 'interop',
    title: 'Status',
    citation: CORE('3.2.2.2'),
    remediation: {
      idp: 'Look up this status in the IdP logs; the second-level code and the message say what it objected to.',
      sp: 'A response that is not a success carries no usable assertion. The usual causes are a rejected AuthnRequest, a user not assigned to the application, or a NameID format the IdP cannot supply.',
    },
    run: onMessage((m) => {
      if (!m.response) return undefined;
      const status = childElements(m.response, SAMLP, 'Status')[0];
      const top = status && childElements(status, SAMLP, 'StatusCode')[0];
      const code = top?.getAttribute('Value');
      const pointer = '/Status/StatusCode';
      if (!code) {
        return {
          severity: 'error',
          detail: 'The Response has no StatusCode, so nothing says whether the login succeeded.',
          evidence: m.evidence,
          pointer,
        };
      }
      if (code === SUCCESS) {
        return {
          severity: 'pass',
          detail: 'The IdP reports Success.',
          evidence: m.evidence,
          pointer,
        };
      }
      const second = top && childElements(top, SAMLP, 'StatusCode')[0]?.getAttribute('Value');
      const said = text(status, SAMLP, 'StatusMessage');
      return {
        severity: 'error',
        detail: `The IdP reports ${code.split(':').pop()}${second ? ` (${second.split(':').pop()})` : ''}, not Success${said ? `, and says: "${said}"` : ''}.`,
        evidence: m.evidence,
        pointer,
      };
    }),
  },
  {
    id: 'saml.assertion.readable',
    protocol: 'saml',
    category: 'interop',
    title: 'Assertion',
    citation: CORE('2.3.3'),
    remediation: {
      sp: 'To inspect what an encrypted assertion says, decrypt it with the SP private key on your own machine and paste the result.',
    },
    run: onMessage((m) => {
      const evidence = m.evidence;
      if (m.assertions.length > 1) {
        return {
          severity: 'warn',
          detail: `The Response carries ${m.assertions.length} assertions. Only the first is judged here, and an SP that reads a different one than it verified can be fooled.`,
          evidence,
        };
      }
      if (m.assertions.length === 1) {
        return { severity: 'pass', detail: 'The assertion is present and readable.', evidence };
      }
      if (m.encrypted.length) {
        return {
          severity: 'info',
          detail:
            'The assertion is encrypted for the SP, so its contents are not judged. Reading it needs the SP private key, which this tool never asks for.',
          evidence,
        };
      }
      return {
        severity: 'info',
        detail:
          'The Response carries no assertion, which is expected when the status is not Success.',
        evidence,
        remediation: {},
      };
    }),
  },
  {
    id: 'saml.response.signed',
    protocol: 'saml',
    category: 'security',
    title: 'What is signed',
    citation: PROFILES('4.1.4.5'),
    remediation: {
      idp: 'Sign the assertion, the Response, or both. Signing the assertion is what most SPs require.',
      sp: 'Never accept an unsigned assertion delivered through the browser: the user can rewrite it.',
    },
    run: onMessage(async (m, ctx): Promise<Result> => {
      const found = (await signatures(ctx, m)).map((s) => s.where);
      const evidence = m.evidence;
      if (!found.length) {
        return {
          severity: 'error',
          detail:
            'Neither the Response nor the assertion is signed, so nothing vouches for what this message says.',
          evidence,
        };
      }
      if (found.length === 2) {
        return {
          severity: 'pass',
          detail: 'Both the Response and the assertion are signed.',
          evidence,
        };
      }
      return found[0] === 'Assertion'
        ? {
            severity: 'pass',
            detail: m.response
              ? 'The assertion is signed. The Response around it is not, so its status and destination are not vouched for.'
              : 'The assertion is signed.',
            evidence,
          }
        : {
            severity: 'pass',
            detail:
              'The Response is signed, which covers the assertion inside it. The assertion has no signature of its own, so an SP that requires signed assertions will refuse it.',
            evidence,
          };
    }),
  },
  {
    id: 'saml.response.signature-reference',
    protocol: 'saml',
    category: 'security',
    title: 'What the signature covers',
    citation: CORE('5.4.2'),
    remediation: {
      idp: 'Sign with a single reference to the ID of the element the signature sits in, using only the enveloped-signature and exclusive canonicalization transforms.',
      sp: 'Reject this message. A signature that covers something other than the element it sits in is how signature wrapping attacks work.',
    },
    run: onMessage(
      async (m, ctx): Promise<Result> =>
        (await signatures(ctx, m)).map(({ where, signature }) =>
          signature.malformed
            ? {
                severity: 'error',
                detail: `The signature in the ${where} cannot be trusted to cover it: ${signature.malformed}.`,
                evidence: m.evidence,
              }
            : {
                severity: 'pass',
                detail: `The signature in the ${where} refers to exactly that element and nothing else.`,
                evidence: m.evidence,
              },
        ),
    ),
  },
  {
    id: 'saml.response.signature',
    protocol: 'saml',
    category: 'security',
    title: 'Signature',
    citation: CORE('5'),
    remediation: {
      idp: 'Publish the certificate that signs responses in the IdP metadata, and keep it there for as long as it signs.',
      sp: 'Reject this message, and confirm the metadata you hold for this IdP is current.',
    },
    run: onMessage(async (m, ctx): Promise<Result> => {
      const known = publisher(ctx, m);
      return (await signatures(ctx, m)).flatMap(
        ({ where, verdict, key, certificate: cert }): Outcome[] => {
          if (!verdict) return [];
          const evidence = m.evidence;
          if (verdict.state === 'unsupported') {
            return [
              {
                severity: 'info',
                detail: `The signature on the ${where} was not verified: ${verdict.why}.`,
                evidence,
                remediation: {},
              },
            ];
          }
          if (verdict.state === 'altered') {
            return [
              {
                severity: 'error',
                detail: `The ${where} was changed after it was signed: its content no longer matches the digest in the signature.`,
                evidence,
              },
            ];
          }
          if (verdict.state === 'wrong-key') {
            return [
              {
                severity: 'error',
                detail: `The signature on the ${where} does not verify against ${known ? 'any certificate the IdP publishes, nor against ' : ''}the certificate carried with it.`,
                evidence,
              },
            ];
          }
          if (key === 'published') {
            return [
              {
                severity: 'pass',
                detail: `The signature on the ${where} verifies against the certificate ${subjectName(cert)} that the IdP publishes.`,
                evidence,
              },
            ];
          }
          return known
            ? [
                {
                  severity: 'error',
                  detail: `The signature on the ${where} verifies only against the certificate ${subjectName(cert)} carried inside the message, which is not one the IdP publishes. Either the IdP changed its key, or someone else signed this.`,
                  evidence,
                },
              ]
            : [
                {
                  severity: 'info',
                  detail: `The signature on the ${where} is consistent with the certificate ${subjectName(cert)} carried next to it. That shows the content was not changed after signing. It does not show who signed it, because anyone can attach their own certificate.`,
                  evidence,
                  remediation: {
                    sp: 'Supply the IdP metadata as well, so the signature can be checked against the certificate the IdP publishes.',
                  },
                },
              ];
        },
      );
    }),
  },
  {
    id: 'saml.response.signature-algorithm',
    protocol: 'saml',
    category: 'security',
    title: 'Signature algorithm',
    citation: {
      label: 'SAML V2.0 Metadata Profile for Algorithm Support, section 4',
      url: 'https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport.html',
    },
    remediation: {
      idp: 'Sign with RSA-SHA256 or stronger, and use SHA-256 or stronger for the digest.',
      sp: 'Ask the IdP to move off SHA-1, and plan to refuse it.',
    },
    run: onMessage(
      async (m, ctx): Promise<Result> =>
        (await signatures(ctx, m)).map(({ where, signature }) => {
          const names = [signature.signatureMethod, signature.digestMethod].map(shortAlgorithm);
          const weak = names.some((name) => /sha1$/i.test(name));
          return {
            severity: weak ? 'warn' : 'pass',
            detail: weak
              ? `The ${where} is signed with ${names[0]} over a ${names[1]} digest. SHA-1 is no longer collision-resistant, and current SAML libraries refuse it by default.`
              : `The ${where} is signed with ${names[0]} over a ${names[1]} digest.`,
            evidence: m.evidence,
          };
        }),
    ),
  },
  {
    id: 'saml.response.issuer',
    protocol: 'saml',
    category: 'conformance',
    title: 'Issuer',
    citation: PROFILES('4.1.4.2'),
    remediation: {
      idp: 'Send the entity ID from the metadata as the Issuer, character for character.',
      sp: 'Compare the Issuer with the entity ID exactly, and check you hold the metadata of the IdP that sent this.',
    },
    run: onMessage((m, ctx) => {
      const known = publisher(ctx, m);
      const issuer = issuerOf(m);
      if (!known) return undefined;
      const evidence = m.evidence;
      if (!issuer) {
        return {
          severity: 'error',
          detail: 'The message names no Issuer, so nothing says which IdP it claims to come from.',
          evidence,
        };
      }
      return issuer === known.entityId
        ? {
            severity: 'pass',
            detail: `The Issuer is ${issuer}, exactly the entity ID in the metadata.`,
            evidence,
          }
        : {
            severity: 'error',
            detail: `The Issuer is ${issuer} but the metadata describes ${known.entityId}. An SP that compares them exactly rejects this message.`,
            evidence,
          };
    }),
  },
  {
    id: 'saml.assertion.time',
    protocol: 'saml',
    category: 'conformance',
    title: 'Validity period',
    citation: CORE('2.5.1'),
    remediation: {
      idp: 'Check the clock on the IdP, and set NotBefore and NotOnOrAfter on Conditions.',
      sp: 'Check the clock on the SP. To judge an assertion as it was when it was issued, evaluate as of that moment.',
    },
    run: onAssertion((assertion, m, ctx) => {
      const conditions = childElements(assertion, SAML, 'Conditions')[0];
      const from = instant(conditions, 'NotBefore');
      const until = instant(conditions, 'NotOnOrAfter');
      const now = ctx.instant.getTime();
      const evidence = m.evidence;
      const pointer = '/Assertion/Conditions';
      if (!until) {
        return {
          severity: 'warn',
          detail:
            'The assertion sets no NotOnOrAfter on its Conditions, so nothing limits how long it can be replayed.',
          evidence,
          pointer,
        };
      }
      if (from && from.getTime() > now) {
        return {
          severity: 'error',
          detail: `The assertion is not valid until ${from.toISOString()}, ${span(from.getTime() - now)} after the evaluation instant. When this happens at login, the SP clock is behind the IdP clock.`,
          evidence,
          pointer,
        };
      }
      if (now >= until.getTime()) {
        return {
          severity: 'warn',
          detail: `The assertion expired at ${until.toISOString()}, ${span(now - until.getTime())} before the evaluation instant.`,
          evidence,
          pointer,
        };
      }
      return {
        severity: 'pass',
        detail: `The assertion is within its validity period and expires at ${until.toISOString()}, in ${span(until.getTime() - now)}.`,
        evidence,
        pointer,
      };
    }),
  },
  {
    id: 'saml.assertion.audience',
    protocol: 'saml',
    category: 'security',
    title: 'Audience',
    citation: PROFILES('4.1.4.2'),
    remediation: {
      idp: 'Add an AudienceRestriction naming the entity ID of the SP the assertion is for.',
      sp: 'Accept the assertion only if an Audience equals your own entity ID exactly.',
    },
    run: onAssertion((assertion, m) => {
      const audiences = descendants(assertion, SAML, 'Audience').flatMap(
        (node) => node.textContent?.trim() || [],
      );
      const pointer = '/Assertion/Conditions/AudienceRestriction';
      return audiences.length
        ? {
            severity: 'info',
            detail: `The assertion is addressed to ${audiences.join(', ')}. Only you can confirm that this is your SP's entity ID; a mismatch here is the most common reason an SP refuses a login.`,
            evidence: m.evidence,
            pointer,
            remediation: {
              sp: 'Accept the assertion only if an Audience equals your own entity ID exactly.',
            },
          }
        : {
            severity: 'warn',
            detail:
              'The assertion names no Audience, so an SP cannot tell it was meant for it, and one issued for another application could be replayed here.',
            evidence: m.evidence,
            pointer,
          };
    }),
  },
  {
    id: 'saml.assertion.subject-confirmation',
    protocol: 'saml',
    category: 'conformance',
    title: 'Subject confirmation',
    citation: PROFILES('4.1.4.2'),
    remediation: {
      idp: 'Send a bearer SubjectConfirmation whose data has a Recipient (the ACS URL) and a NotOnOrAfter, and no NotBefore.',
      sp: 'Accept the assertion only if the Recipient is your ACS URL and InResponseTo matches a request you sent.',
    },
    run: onAssertion((assertion, m) => {
      const subject = childElements(assertion, SAML, 'Subject')[0];
      const bearer = (subject ? childElements(subject, SAML, 'SubjectConfirmation') : []).find(
        (confirmation) => confirmation.getAttribute('Method') === BEARER,
      );
      const evidence = m.evidence;
      const pointer = '/Assertion/Subject/SubjectConfirmation';
      if (!bearer) {
        return {
          severity: 'error',
          detail:
            'The assertion has no bearer SubjectConfirmation, which browser single sign-on requires.',
          evidence,
          pointer,
        };
      }
      const data = childElements(bearer, SAML, 'SubjectConfirmationData')[0];
      const problems = [
        ...(data?.getAttribute('Recipient') ? [] : ['it has no Recipient']),
        ...(data?.getAttribute('NotOnOrAfter') ? [] : ['it has no NotOnOrAfter']),
        ...(data?.getAttribute('NotBefore')
          ? ['it sets NotBefore, which is not allowed here']
          : []),
      ];
      if (problems.length) {
        return {
          severity: 'error',
          detail: `The bearer SubjectConfirmation is not usable for browser single sign-on: ${problems.join(', ')}.`,
          evidence,
          pointer,
        };
      }
      const request = data?.getAttribute('InResponseTo');
      return {
        severity: 'pass',
        detail: `The assertion is confirmed as a bearer assertion for ${data?.getAttribute('Recipient')}, ${request ? `in response to request ${request}` : 'not in response to any request (IdP-initiated)'}.`,
        evidence,
        pointer,
      };
    }),
  },
];
