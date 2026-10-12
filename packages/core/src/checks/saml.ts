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
    title: 'Metadata document is retrievable',
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
    title: 'Metadata is well-formed XML with a metadata root',
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
    title: 'entityID is present and at most 1024 characters',
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
          detail: `entityID is the template ${id}. This is multi-tenant metadata; the Issuer in real assertions carries a tenant-specific value, so configure the SP from the tenant's own metadata.`,
          evidence,
          pointer,
        };
      }
      return id !== id.trim()
        ? {
            severity: 'warn',
            detail:
              'entityID has leading or trailing whitespace, which breaks exact-match comparison.',
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
    title: 'Entity declares an SSO role',
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
    title: 'Roles declare SAML 2.0 protocol support',
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
    title: 'Metadata has not passed its validUntil',
    citation: METADATA('2.3.2'),
    remediation: {
      idp: 'Republish metadata with a later validUntil.',
      sp: 'Refresh the stored metadata; consumers must not use expired metadata.',
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
    title: 'Metadata carries a signature',
    citation: METADATA('3'),
    remediation: {
      sp: 'Unsigned metadata is trusted only as far as the channel it arrived over; fetch it over TLS from the IdP itself and pin the certificate out of band.',
    },
    run: onEntity(({ evidence, entity }) => {
      const signed =
        childElements(entity, DS, 'Signature').length > 0 ||
        childElements(entity.ownerDocument?.documentElement ?? entity, DS, 'Signature').length > 0;
      return {
        severity: 'info',
        detail: signed
          ? 'A ds:Signature is present. It has not been verified.'
          : 'The metadata is unsigned, which is common and acceptable when it is retrieved over TLS from the entity itself.',
        evidence,
      };
    }),
  },
  {
    id: 'saml.metadata.endpoints-https',
    protocol: 'saml',
    category: 'security',
    title: 'Every endpoint location uses https',
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
    title: 'IdP publishes a usable SingleSignOnService',
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
            detail: `SSO bindings are [${bindings.join(', ')}]; neither front-channel binding that browsers SSO relies on is offered.`,
            evidence,
          };
    }),
  },
  {
    id: 'saml.idp.signing-key',
    protocol: 'saml',
    category: 'conformance',
    title: 'IdP publishes a signing certificate',
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
            detail: 'No signing certificate is published, so no assertion can be verified.',
            evidence: s.evidence,
          };
    }),
  },
  {
    id: 'saml.idp.signing-key-rollover',
    protocol: 'saml',
    category: 'interop',
    title: 'IdP signing certificate rollover state',
    citation: METADATA('2.4.1.1'),
    remediation: {
      sp: 'Store and accept every published signing certificate, not only the first, so a rotation does not cause an outage.',
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
            ? `${signing.length} signing certificates are published, which indicates a rotation in progress or staged: ${list}. Any of them may sign.`
            : `One signing certificate is published: ${list}.`,
        evidence: s.evidence,
      };
    }),
  },
  {
    id: 'saml.idp.want-authn-requests-signed',
    protocol: 'saml',
    category: 'interop',
    title: 'IdP requirement for signed AuthnRequests',
    citation: METADATA('2.4.3'),
    remediation: {
      sp: 'Sign AuthnRequests and give the IdP the SP signing certificate when this is true.',
    },
    run: onEntity(({ evidence, idp }) => {
      if (!idp) return undefined;
      const want = idp.getAttribute('WantAuthnRequestsSigned') === 'true';
      return {
        severity: 'info',
        detail: want
          ? 'WantAuthnRequestsSigned is true: unsigned AuthnRequests will be rejected.'
          : 'WantAuthnRequestsSigned is not true: unsigned AuthnRequests are accepted.',
        evidence,
      };
    }),
  },
  {
    id: 'saml.sp.acs',
    protocol: 'saml',
    category: 'conformance',
    title: 'SP publishes a usable AssertionConsumerService',
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
    title: 'SP asks for signed assertions',
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
              'WantAssertionsSigned is not true, so IdPs may sign only the Response. Verifying the assertion itself is the stronger defence against signature wrapping.',
            evidence,
          };
    }),
  },
  {
    id: 'saml.cert.readable',
    protocol: 'saml',
    category: 'conformance',
    title: 'Published certificates are parseable X.509',
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
    title: 'Certificates are within their validity period',
    citation: METADATA('2.4.1.1'),
    remediation: {
      idp: 'Rotate the certificate and publish the replacement before removing the old one.',
      sp: 'Many SP stacks reject assertions signed with an expired certificate even though SAML itself does not require the check; confirm how yours behaves.',
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
    title: 'Certificate keys are at least 2048-bit RSA or elliptic curve',
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
    title: 'Advertised NameID formats',
    citation: METADATA('2.4.2'),
    remediation: {
      sp: 'Do not key accounts on a transient NameID, and treat emailAddress as mutable; prefer a persistent identifier or an immutable attribute.',
    },
    run: onEntity((s) => {
      const formats = roles(s).flatMap(([, el]) =>
        childElements(el, MD, 'NameIDFormat').map((f) => (f.textContent ?? '').trim()),
      );
      return {
        severity: 'info',
        detail: formats.length
          ? `NameID formats: ${formats.map((f) => f.split(':').pop()).join(', ')}.`
          : 'No NameIDFormat is advertised, so the format is whatever is negotiated per request.',
        evidence: s.evidence,
      };
    }),
  },
];
