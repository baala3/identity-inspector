import type { Element } from '@xmldom/xmldom';
import type { Check, CheckContext, Citation, Evidence, Outcome } from '../model.js';
import { childElements, descendants, isHttps, xml } from '../parse.js';
import { type Certificate, parseCertificate } from '../x509.js';

export const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
export const DS = 'http://www.w3.org/2000/09/xmldsig#';
const SAML2_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';
const BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:';
const DAY = 86_400_000;

const METADATA = (section: string): Citation => ({
  label: `SAML 2.0 Metadata, section ${section}`,
  url: 'https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf',
});

interface Subject {
  evidence: Evidence;
  entity: Element;
  idp: Element | undefined;
  sp: Element | undefined;
}

const metadata = (ctx: CheckContext) =>
  ctx.workspace.evidence.find((e) => e.kind === 'saml.metadata');

/** The first entity in the metadata, which is the one every entity-level check judges. */
function subject(ctx: CheckContext): Subject | undefined {
  const evidence = metadata(ctx);
  const document = evidence && xml(evidence).document;
  if (!evidence || !document) return undefined;
  const root = document.documentElement;
  const entity =
    root?.namespaceURI === MD && root.localName === 'EntityDescriptor'
      ? root
      : descendants(document, MD, 'EntityDescriptor')[0];
  if (!entity) return undefined;
  return {
    evidence,
    entity,
    idp: childElements(entity, MD, 'IDPSSODescriptor')[0],
    sp: childElements(entity, MD, 'SPSSODescriptor')[0],
  };
}

function onEntity(
  body: (s: Subject, ctx: CheckContext) => Outcome | Outcome[] | undefined,
): Check['run'] {
  return (ctx) => {
    const s = subject(ctx);
    return s ? body(s, ctx) : undefined;
  };
}

const roles = (s: Subject) =>
  [
    s.idp && (['IDPSSODescriptor', s.idp] as const),
    s.sp && (['SPSSODescriptor', s.sp] as const),
  ].filter((r) => r !== undefined);

interface Key {
  role: string;
  use: string;
  cert?: Certificate;
  error?: string;
}

function keys(s: Subject): Key[] {
  return roles(s).flatMap(([role, element]) =>
    childElements(element, MD, 'KeyDescriptor').flatMap((descriptor) =>
      descendants(descriptor, DS, 'X509Certificate').map((node): Key => {
        // An absent use means the key serves both signing and encryption.
        const use = descriptor.getAttribute('use') || 'signing+encryption';
        try {
          return { role, use, cert: parseCertificate(node.textContent ?? '') };
        } catch (error) {
          return { role, use, error: error instanceof Error ? error.message : String(error) };
        }
      }),
    ),
  );
}

const describe = (key: Key) => `${key.role} ${key.use} certificate "${key.cert?.subject ?? '?'}"`;

const short = (binding: string | null) => (binding ?? '').replace(BINDING, '');

const endpoints = (role: Element, name: string) => childElements(role, MD, name);

export const samlChecks: Check[] = [
  {
    id: 'saml.metadata.reachable',
    protocol: 'saml',
    category: 'conformance',
    title: 'Metadata URL',
    citation: METADATA('4.1'),
    remediation: {
      idp: 'Publish metadata at a stable, unauthenticated URL.',
      sp: 'If the IdP has no metadata URL, obtain the XML from the tenant admin and inspect it directly.',
    },
    run: (ctx) => {
      const evidence = metadata(ctx);
      if (!evidence?.fetch) return undefined;
      const { status, error } = evidence.fetch;
      return status === 200
        ? { severity: 'pass', detail: `${evidence.source} returned 200.`, evidence }
        : {
            severity: 'error',
            detail: `${evidence.source} is unusable: ${status === 0 ? `request failed: ${error ?? 'no response'}` : `HTTP ${status}`}.`,
            evidence,
          };
    },
  },
  {
    id: 'saml.metadata.well-formed',
    protocol: 'saml',
    category: 'conformance',
    title: 'Metadata XML',
    citation: METADATA('2.3'),
    remediation: {
      idp: 'Publish an EntityDescriptor or EntitiesDescriptor in the SAML metadata namespace.',
    },
    run: (ctx) => {
      const evidence = metadata(ctx);
      if (!evidence || (evidence.fetch && evidence.fetch.status !== 200)) return undefined;
      const parsed = xml(evidence);
      if (!parsed.document)
        return { severity: 'error', detail: `Not parseable: ${parsed.error}.`, evidence };
      const root = parsed.document.documentElement;
      if (
        root?.namespaceURI !== MD ||
        !['EntityDescriptor', 'EntitiesDescriptor'].includes(root.localName ?? '')
      ) {
        return {
          severity: 'error',
          detail: `Root element is {${root?.namespaceURI ?? ''}}${root?.localName}, not a SAML metadata descriptor.`,
          evidence,
        };
      }
      const count = descendants(parsed.document, MD, 'EntityDescriptor').length;
      return root.localName === 'EntitiesDescriptor'
        ? {
            severity: 'info',
            detail: `This is an aggregate of ${count} entities. Only the first is inspected.`,
            evidence,
          }
        : { severity: 'pass', detail: 'Root element is md:EntityDescriptor.', evidence };
    },
  },
  {
    id: 'saml.metadata.entity-id',
    protocol: 'saml',
    category: 'conformance',
    title: 'Entity ID',
    citation: METADATA('2.3.2'),
    remediation: { idp: 'Set a stable URI as entityID.', sp: 'Set a stable URI as entityID.' },
    run: onEntity(({ evidence, entity }) => {
      const id = entity.getAttribute('entityID') ?? '';
      const pointer = '/EntityDescriptor/@entityID';
      if (!id)
        return {
          severity: 'error',
          detail: 'The EntityDescriptor has no entityID.',
          evidence,
          pointer,
        };
      if (id.length > 1024)
        return {
          severity: 'error',
          detail: `entityID is ${id.length} characters.`,
          evidence,
          pointer,
        };
      if (/[{}]/.test(id)) {
        return {
          severity: 'warn',
          detail: `The entityID is ${id}, which contains a placeholder (a template). This is shared multi-tenant metadata. Real responses carry a tenant-specific Issuer, so set up your SP from the metadata of your own tenant.`,
          evidence,
          pointer,
        };
      }
      return id !== id.trim()
        ? {
            severity: 'warn',
            detail:
              'The entityID has a space at the start or end. Entity IDs are compared exactly, so this will cause mismatches.',
            evidence,
            pointer,
          }
        : { severity: 'pass', detail: `entityID is ${id}.`, evidence, pointer };
    }),
  },
  {
    id: 'saml.metadata.sso-role',
    protocol: 'saml',
    category: 'conformance',
    title: 'IdP or SP role',
    citation: METADATA('2.4'),
    remediation: { idp: 'Include an IDPSSODescriptor.', sp: 'Include an SPSSODescriptor.' },
    run: onEntity((s) => {
      const names = roles(s).map(([name]) => name);
      return names.length
        ? { severity: 'pass', detail: `Declared roles: ${names.join(', ')}.`, evidence: s.evidence }
        : {
            severity: 'error',
            detail: 'Neither IDPSSODescriptor nor SPSSODescriptor is present.',
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.metadata.protocol-support',
    protocol: 'saml',
    category: 'conformance',
    title: 'SAML 2.0 support',
    citation: METADATA('2.4.1'),
    remediation: { idp: `Set protocolSupportEnumeration to include ${SAML2_PROTOCOL}.` },
    run: onEntity((s) => {
      if (!roles(s).length) return undefined;
      const missing = roles(s)
        .filter(
          ([, el]) =>
            !(el.getAttribute('protocolSupportEnumeration') ?? '')
              .split(/\s+/)
              .includes(SAML2_PROTOCOL),
        )
        .map(([name]) => name);
      return missing.length
        ? {
            severity: 'error',
            detail: `${missing.join(', ')} does not list the SAML 2.0 protocol URI.`,
            evidence: s.evidence,
          }
        : {
            severity: 'pass',
            detail: 'Every role lists the SAML 2.0 protocol URI.',
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.metadata.valid-until',
    protocol: 'saml',
    category: 'conformance',
    title: 'Metadata expiry',
    citation: METADATA('2.3.2'),
    remediation: {
      idp: 'Republish metadata with a later validUntil.',
      sp: 'Download the metadata again. Expired metadata must not be used.',
    },
    run: onEntity(({ evidence, entity }, ctx) => {
      const value =
        entity.getAttribute('validUntil') ||
        entity.ownerDocument?.documentElement?.getAttribute('validUntil');
      if (!value) return undefined;
      const until = new Date(value);
      const pointer = '/EntityDescriptor/@validUntil';
      if (Number.isNaN(until.getTime()))
        return {
          severity: 'error',
          detail: `validUntil "${value}" is not a dateTime.`,
          evidence,
          pointer,
        };
      return ctx.instant > until
        ? {
            severity: 'error',
            detail: `Metadata expired at ${until.toISOString()}.`,
            evidence,
            pointer,
          }
        : {
            severity: 'pass',
            detail: `Metadata is valid until ${until.toISOString()}.`,
            evidence,
            pointer,
          };
    }),
  },
  {
    id: 'saml.metadata.signed',
    protocol: 'saml',
    category: 'security',
    title: 'Metadata signature',
    citation: METADATA('3'),
    remediation: {
      sp: 'Only trust unsigned metadata that you fetched over https from the IdP itself, and confirm the certificate with the IdP admin through another channel.',
    },
    run: onEntity(({ evidence, entity }) => {
      const signed =
        childElements(entity, DS, 'Signature').length > 0 ||
        childElements(entity.ownerDocument?.documentElement ?? entity, DS, 'Signature').length > 0;
      return {
        severity: 'info',
        detail: signed
          ? 'The metadata has a signature. It has not been verified by this tool.'
          : 'The metadata is unsigned. That is common, and fine as long as you download it over https directly from its owner.',
        evidence,
      };
    }),
  },
  {
    id: 'saml.metadata.endpoints-https',
    protocol: 'saml',
    category: 'security',
    title: 'HTTPS on endpoints',
    citation: METADATA('2.2.2'),
    remediation: { idp: 'Serve every endpoint over TLS.', sp: 'Serve every endpoint over TLS.' },
    run: onEntity(({ evidence, entity }) => {
      const located = descendants(entity, MD, '*').filter((el) => el.hasAttribute('Location'));
      if (!located.length) return undefined;
      const bad = located.filter((el) => !isHttps(el.getAttribute('Location')));
      return bad.length
        ? {
            severity: 'error',
            detail: `Not https: ${bad.map((el) => `${el.localName} ${el.getAttribute('Location')}`).join(', ')}.`,
            evidence,
          }
        : {
            severity: 'pass',
            detail: `All ${located.length} endpoint locations are https.`,
            evidence,
          };
    }),
  },
  {
    id: 'saml.idp.sso-service',
    protocol: 'saml',
    category: 'conformance',
    title: 'Sign-in endpoint',
    citation: METADATA('2.4.3'),
    remediation: {
      idp: 'Publish a SingleSignOnService with the HTTP-Redirect or HTTP-POST binding.',
    },
    run: onEntity(({ evidence, idp }) => {
      if (!idp) return undefined;
      const bindings = endpoints(idp, 'SingleSignOnService').map((el) =>
        short(el.getAttribute('Binding')),
      );
      if (!bindings.length)
        return {
          severity: 'error',
          detail: 'The IDPSSODescriptor has no SingleSignOnService.',
          evidence,
        };
      return bindings.some((b) => b === 'HTTP-Redirect' || b === 'HTTP-POST')
        ? { severity: 'pass', detail: `SSO bindings: ${bindings.join(', ')}.`, evidence }
        : {
            severity: 'warn',
            detail: `The IdP offers only [${bindings.join(', ')}] for sign-in. Browser sign-in needs HTTP-Redirect or HTTP-POST, and neither is offered.`,
            evidence,
          };
    }),
  },
  {
    id: 'saml.idp.signing-key',
    protocol: 'saml',
    category: 'conformance',
    title: 'Signing certificate',
    citation: METADATA('2.4.1.1'),
    remediation: {
      idp: 'Publish a KeyDescriptor with use="signing" holding the assertion signing certificate.',
    },
    run: onEntity((s) => {
      if (!s.idp) return undefined;
      const signing = keys(s).filter(
        (k) => k.role === 'IDPSSODescriptor' && k.use !== 'encryption',
      );
      return signing.length
        ? {
            severity: 'pass',
            detail: `${signing.length} signing certificate(s) published.`,
            evidence: s.evidence,
          }
        : {
            severity: 'error',
            detail:
              'No signing certificate is published, so an SP has nothing to verify responses against.',
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.idp.signing-key-rollover',
    protocol: 'saml',
    category: 'interop',
    title: 'Signing certificate rotation',
    citation: METADATA('2.4.1.1'),
    remediation: {
      sp: 'Save and accept every published signing certificate, not only the first. Otherwise sign-in breaks the day the IdP switches.',
    },
    run: onEntity((s) => {
      if (!s.idp) return undefined;
      const signing = keys(s).filter(
        (k) => k.role === 'IDPSSODescriptor' && k.use !== 'encryption' && k.cert,
      );
      if (!signing.length) return undefined;
      const list = signing
        .map((k) => `"${k.cert?.subject}" until ${k.cert?.notAfter.toISOString().slice(0, 10)}`)
        .join('; ');
      return {
        severity: 'info',
        detail:
          signing.length > 1
            ? `${signing.length} signing certificates are published, which usually means the IdP is rotating to a new one: ${list}. The IdP may sign with any of them.`
            : `One signing certificate is published: ${list}.`,
        evidence: s.evidence,
      };
    }),
  },
  {
    id: 'saml.idp.want-authn-requests-signed',
    protocol: 'saml',
    category: 'interop',
    title: 'Signed sign-in requests',
    citation: METADATA('2.4.3'),
    remediation: {
      sp: 'If signing is required, sign your AuthnRequests and give the IdP admin your SP signing certificate.',
    },
    run: onEntity(({ evidence, idp }) => {
      if (!idp) return undefined;
      const want = idp.getAttribute('WantAuthnRequestsSigned') === 'true';
      return {
        severity: 'info',
        detail: want
          ? 'The IdP requires signed sign-in requests (WantAuthnRequestsSigned is true). Unsigned AuthnRequests will be rejected.'
          : 'The IdP does not require signed sign-in requests. Unsigned AuthnRequests are accepted.',
        evidence,
      };
    }),
  },
  {
    id: 'saml.sp.acs',
    protocol: 'saml',
    category: 'conformance',
    title: 'Assertion Consumer Service (ACS)',
    citation: METADATA('2.4.4'),
    remediation: { sp: 'Publish an HTTP-POST AssertionConsumerService with a unique index.' },
    run: onEntity(({ evidence, sp }) => {
      if (!sp) return undefined;
      const acs = endpoints(sp, 'AssertionConsumerService');
      if (!acs.length)
        return {
          severity: 'error',
          detail: 'The SPSSODescriptor has no AssertionConsumerService.',
          evidence,
        };
      const indexes = acs.map((el) => el.getAttribute('index') ?? '');
      const faults = [
        indexes.some((i) => i === '') && 'an endpoint has no index',
        new Set(indexes).size !== indexes.length && 'index values are not unique',
        acs.filter((el) => el.getAttribute('isDefault') === 'true').length > 1 &&
          'more than one endpoint is marked default',
        !acs.some((el) => short(el.getAttribute('Binding')) === 'HTTP-POST') &&
          'no endpoint uses HTTP-POST',
      ].filter(Boolean);
      return faults.length
        ? {
            severity: 'error',
            detail: `AssertionConsumerService problems: ${faults.join('; ')}.`,
            evidence,
          }
        : {
            severity: 'pass',
            detail: `${acs.length} AssertionConsumerService endpoint(s), indexes ${indexes.join(', ')}.`,
            evidence,
          };
    }),
  },
  {
    id: 'saml.sp.want-assertions-signed',
    protocol: 'saml',
    category: 'security',
    title: 'Signed assertions',
    citation: METADATA('2.4.4'),
    remediation: {
      sp: 'Set WantAssertionsSigned="true" and reject any assertion without its own valid signature.',
    },
    run: onEntity(({ evidence, sp }) => {
      if (!sp) return undefined;
      return sp.getAttribute('WantAssertionsSigned') === 'true'
        ? { severity: 'pass', detail: 'WantAssertionsSigned is true.', evidence }
        : {
            severity: 'warn',
            detail:
              'The SP does not ask for the assertion itself to be signed, so an IdP may sign only the outer Response. Requiring a signature on the assertion gives stronger protection against tampering (signature wrapping attacks).',
            evidence,
          };
    }),
  },
  {
    id: 'saml.cert.readable',
    protocol: 'saml',
    category: 'conformance',
    title: 'Certificate format',
    citation: METADATA('2.4.1.1'),
    remediation: { idp: 'Publish base64 DER certificates in ds:X509Certificate.' },
    run: onEntity((s) => {
      const all = keys(s);
      if (!all.length) return undefined;
      const broken = all.filter((k) => !k.cert);
      return broken.length
        ? {
            severity: 'error',
            detail: `${broken.length} of ${all.length} certificates cannot be parsed (${broken[0]?.error}).`,
            evidence: s.evidence,
          }
        : {
            severity: 'pass',
            detail: `All ${all.length} certificates parse.`,
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.cert.validity',
    protocol: 'saml',
    category: 'interop',
    title: 'Certificate expiry',
    citation: METADATA('2.4.1.1'),
    remediation: {
      idp: 'Issue a new certificate and publish it next to the old one before removing the old one.',
      sp: 'SAML does not require checking certificate expiry, but many SP libraries reject expired certificates anyway. Check what yours does.',
    },
    run: onEntity((s, ctx) => {
      const certs = keys(s).filter((k) => k.cert);
      if (!certs.length) return undefined;
      const outcomes: Outcome[] = [];
      for (const key of certs) {
        const { notBefore, notAfter } = key.cert as Certificate;
        const days = Math.floor((notAfter.getTime() - ctx.instant.getTime()) / DAY);
        if (ctx.instant > notAfter) {
          outcomes.push({
            severity: 'error',
            detail: `${describe(key)} expired on ${notAfter.toISOString()}.`,
            evidence: s.evidence,
          });
        } else if (ctx.instant < notBefore) {
          outcomes.push({
            severity: 'error',
            detail: `${describe(key)} is not valid until ${notBefore.toISOString()}.`,
            evidence: s.evidence,
          });
        } else if (days <= 30) {
          outcomes.push({
            severity: 'warn',
            detail: `${describe(key)} expires in ${days} day(s), on ${notAfter.toISOString()}.`,
            evidence: s.evidence,
          });
        }
      }
      return outcomes.length
        ? outcomes
        : {
            severity: 'pass',
            detail: `All ${certs.length} certificates are valid for more than 30 days.`,
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.cert.key-strength',
    protocol: 'saml',
    category: 'security',
    title: 'Certificate key size',
    citation: {
      label: 'NIST SP 800-131A Rev. 2, section 3',
      url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final',
    },
    remediation: { idp: 'Reissue the certificate with an RSA key of 2048 bits or more.' },
    run: onEntity((s) => {
      const rsa = keys(s).filter((k) => k.cert?.keyType === 'RSA');
      if (!rsa.length) return undefined;
      const weak = rsa.filter((k) => (k.cert?.keyBits ?? 0) < 2048);
      return weak.length
        ? {
            severity: 'error',
            detail: `Undersized keys: ${weak.map((k) => `${describe(k)} (${k.cert?.keyBits} bits)`).join(', ')}.`,
            evidence: s.evidence,
          }
        : {
            severity: 'pass',
            detail: `RSA key sizes: ${rsa.map((k) => k.cert?.keyBits).join(', ')} bits.`,
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.metadata.nameid-formats',
    protocol: 'saml',
    category: 'interop',
    title: 'NameID formats',
    citation: METADATA('2.4.2'),
    remediation: {
      sp: 'Do not use a transient NameID as the account key, and remember that email addresses change. Prefer a persistent ID or an attribute that never changes.',
    },
    run: onEntity((s) => {
      const formats = roles(s).flatMap(([, el]) =>
        childElements(el, MD, 'NameIDFormat').map((f) => (f.textContent ?? '').trim()),
      );
      return {
        severity: 'info',
        detail: formats.length
          ? `NameID formats: ${formats.map((f) => f.split(':').pop()).join(', ')}.`
          : 'No NameIDFormat is advertised, so the format is decided per request.',
        evidence: s.evidence,
      };
    }),
  },
];
