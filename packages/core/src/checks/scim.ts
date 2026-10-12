import type { Check, CheckContext, Citation, Evidence, Outcome } from '../model.js';
import { isHttps, type Json, json, objects, strings } from '../parse.js';

const SCHEMA = (section: string): Citation => ({
  label: `RFC 7643 (SCIM Core Schema), section ${section}`,
  url: `https://www.rfc-editor.org/rfc/rfc7643#section-${section}`,
});
const PROTOCOL = (section: string): Citation => ({
  label: `RFC 7644 (SCIM Protocol), section ${section}`,
  url: `https://www.rfc-editor.org/rfc/rfc7644#section-${section}`,
});

const CORE = 'urn:ietf:params:scim:schemas:core:2.0:';
const ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';
const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const KINDS = ['scim.service-provider-config', 'scim.resource-types', 'scim.schemas'] as const;

const all = (ctx: CheckContext) => ctx.workspace.evidence.filter((e) => e.kind.startsWith('scim.'));
const find = (ctx: CheckContext, kind: Evidence['kind']) =>
  ctx.workspace.evidence.find((e) => e.kind === kind);
const ok = (e: Evidence | undefined): e is Evidence =>
  e?.fetch?.status === 200 && json(e) !== undefined;
const path = (e: Evidence) => (e.source ? new URL(e.source).pathname.split('/').pop() : e.kind);

/** Discovery endpoints answer with either a ListResponse or a bare array. */
function resources(evidence: Evidence): Json[] {
  const doc = json(evidence);
  if (doc) return objects(doc.Resources);
  try {
    return objects(JSON.parse(evidence.raw));
  } catch {
    return [];
  }
}

function onConfig(
  body: (doc: Json, evidence: Evidence) => Outcome | Outcome[] | undefined,
): Check['run'] {
  return (ctx) => {
    const evidence = find(ctx, 'scim.service-provider-config');
    const doc = ok(evidence) ? json(evidence) : undefined;
    return evidence && doc ? body(doc, evidence) : undefined;
  };
}

const supported = (doc: Json, feature: string) =>
  (doc[feature] as Json | undefined)?.supported === true;

export const scimChecks: Check[] = [
  {
    id: 'scim.base.https',
    protocol: 'scim',
    category: 'security',
    title: 'SCIM base URL uses https',
    citation: PROTOCOL('7.1'),
    remediation: {
      'scim-server': 'Serve SCIM only over TLS; bearer tokens travel on every request.',
    },
    run: (ctx) =>
      isHttps(ctx.workspace.target.input)
        ? { severity: 'pass', detail: `${ctx.workspace.target.input} is https.` }
        : { severity: 'error', detail: `${ctx.workspace.target.input} is not https.` },
  },
  {
    id: 'scim.discovery.reachable',
    protocol: 'scim',
    category: 'conformance',
    title: 'Discovery endpoints respond',
    citation: PROTOCOL('4'),
    remediation: {
      'scim-server':
        'Implement /ServiceProviderConfig, /ResourceTypes, and /Schemas under the base URL.',
      'scim-client':
        'Check the base URL: it normally ends in /scim/v2 or a tenant-specific prefix, with no trailing resource name.',
    },
    run: (ctx) =>
      all(ctx).map((evidence): Outcome => {
        const status = evidence.fetch?.status ?? 0;
        if (status === 200) {
          return json(evidence) || resources(evidence).length
            ? { severity: 'pass', detail: `${path(evidence)} returned 200 with JSON.`, evidence }
            : {
                severity: 'error',
                detail: `${path(evidence)} returned 200 but the body is not JSON.`,
                evidence,
              };
        }
        if (status === 401 || status === 403) {
          return {
            severity: 'info',
            detail: `${path(evidence)} requires authentication (HTTP ${status}), so its content was not inspected. Supply a token to the CLI to go further.`,
            evidence,
          };
        }
        return {
          severity: 'error',
          detail: `${path(evidence)} is unusable: ${status === 0 ? `request failed: ${evidence.fetch?.error ?? 'no response'}` : `HTTP ${status}`}.`,
          evidence,
        };
      }),
  },
  {
    id: 'scim.discovery.content-type',
    protocol: 'scim',
    category: 'conformance',
    title: 'Responses are served as application/scim+json',
    citation: PROTOCOL('3.8'),
    remediation: {
      'scim-server': 'Return Content-Type: application/scim+json on every SCIM response.',
    },
    run: (ctx) => {
      const answered = all(ctx).filter((e) => e.fetch?.status === 200);
      if (!answered.length) return undefined;
      const off = answered.filter(
        (e) => !/^application\/scim\+json\b/i.test(e.fetch?.headers['content-type'] ?? ''),
      );
      return off.length
        ? {
            severity: 'warn',
            detail: `Not application/scim+json: ${off.map((e) => `${path(e)} (${e.fetch?.headers['content-type'] ?? 'none'})`).join(', ')}.`,
            evidence: off[0] as Evidence,
          }
        : {
            severity: 'pass',
            detail: 'Every discovery response is application/scim+json.',
            evidence: answered[0] as Evidence,
          };
    },
  },
  {
    id: 'scim.error.shape',
    protocol: 'scim',
    category: 'conformance',
    title: 'Refusals use the SCIM error format',
    citation: PROTOCOL('3.12'),
    remediation: {
      'scim-server': `Return a JSON body with schemas ["${ERROR}"] and a string "status" on every error, including 401.`,
    },
    run: (ctx) => {
      const refused = all(ctx).filter((e) => (e.fetch?.status ?? 0) >= 400);
      if (!refused.length) return undefined;
      const bad = refused.filter((e) => !strings(json(e)?.schemas).includes(ERROR));
      return bad.length
        ? {
            severity: 'warn',
            detail: `${bad.map((e) => `${path(e)} (HTTP ${e.fetch?.status})`).join(', ')} did not return a SCIM Error body. Provisioning clients surface these as opaque failures.`,
            evidence: bad[0] as Evidence,
          }
        : {
            severity: 'pass',
            detail: 'Error responses use the SCIM Error schema.',
            evidence: refused[0] as Evidence,
          };
    },
  },
  {
    id: 'scim.config.schema',
    protocol: 'scim',
    category: 'conformance',
    title: 'ServiceProviderConfig declares its schema and required attributes',
    citation: SCHEMA('5'),
    remediation: {
      'scim-server':
        'Return patch, bulk, filter, changePassword, sort, etag, and authenticationSchemes with the ServiceProviderConfig schema URN.',
    },
    run: onConfig((doc, evidence) => {
      const faults: string[] = [];
      if (!strings(doc.schemas).includes(`${CORE}ServiceProviderConfig`))
        faults.push('schemas lacks the ServiceProviderConfig URN');
      const missing = [
        'patch',
        'bulk',
        'filter',
        'changePassword',
        'sort',
        'etag',
        'authenticationSchemes',
      ].filter((key) => doc[key] === undefined);
      if (missing.length) faults.push(`missing ${missing.join(', ')}`);
      return faults.length
        ? { severity: 'error', detail: `${faults.join('; ')}.`, evidence }
        : {
            severity: 'pass',
            detail: 'Schema URN and all required attributes are present.',
            evidence,
          };
    }),
  },
  {
    id: 'scim.config.patch',
    protocol: 'scim',
    category: 'interop',
    title: 'PATCH is supported',
    citation: PROTOCOL('3.5.2'),
    remediation: {
      'scim-server':
        'Implement PATCH. Entra ID sends every update and every deactivation as PATCH and has no PUT fallback.',
    },
    run: onConfig((doc, evidence) =>
      supported(doc, 'patch')
        ? {
            severity: 'pass',
            detail: 'patch.supported is true.',
            evidence,
            pointer: '/patch/supported',
          }
        : {
            severity: 'error',
            detail:
              'patch.supported is not true. Entra ID provisioning cannot update or deactivate users without PATCH.',
            evidence,
            pointer: '/patch/supported',
          },
    ),
  },
  {
    id: 'scim.config.filter',
    protocol: 'scim',
    category: 'interop',
    title: 'Filtering is supported',
    citation: PROTOCOL('3.4.2.2'),
    remediation: {
      'scim-server':
        'Support at least "eq" filters on userName, externalId, and displayName. Entra ID and Okta both look users up by filter before creating them.',
    },
    run: onConfig((doc, evidence) => {
      const pointer = '/filter/supported';
      if (!supported(doc, 'filter')) {
        return {
          severity: 'error',
          detail:
            'filter.supported is not true. Directory clients match existing accounts with a userName filter, so every sync would create duplicates or fail.',
          evidence,
          pointer,
        };
      }
      const max = (doc.filter as Json).maxResults;
      return {
        severity: 'pass',
        detail: `filter.supported is true, maxResults ${String(max ?? 'unspecified')}.`,
        evidence,
        pointer,
      };
    }),
  },
  {
    id: 'scim.config.auth-schemes',
    protocol: 'scim',
    category: 'conformance',
    title: 'Authentication schemes are declared',
    citation: SCHEMA('5'),
    remediation: {
      'scim-server':
        'List each accepted scheme, for example oauthbearertoken, in authenticationSchemes.',
    },
    run: onConfig((doc, evidence) => {
      const schemes = objects(doc.authenticationSchemes).map((s) =>
        String(s.type ?? s.name ?? '?'),
      );
      return schemes.length
        ? {
            severity: 'pass',
            detail: `Declared schemes: ${schemes.join(', ')}.`,
            evidence,
            pointer: '/authenticationSchemes',
          }
        : {
            severity: 'warn',
            detail: 'authenticationSchemes is empty, so clients cannot tell how to authenticate.',
            evidence,
            pointer: '/authenticationSchemes',
          };
    }),
  },
  {
    id: 'scim.config.features',
    protocol: 'scim',
    category: 'interop',
    title: 'Optional feature support',
    citation: SCHEMA('5'),
    run: onConfig((doc, evidence) => {
      const features = ['bulk', 'sort', 'etag', 'changePassword'].map(
        (f) => `${f} ${supported(doc, f) ? 'yes' : 'no'}`,
      );
      return {
        severity: 'info',
        detail: `Advertised: ${features.join(', ')}. These are claims read from the document, not tested behaviour.`,
        evidence,
      };
    }),
  },
  {
    id: 'scim.resource-types.user',
    protocol: 'scim',
    category: 'conformance',
    title: 'A User resource type is published',
    citation: SCHEMA('6'),
    remediation: {
      'scim-server': `Publish a resource type with schema ${CORE}User and endpoint /Users.`,
    },
    run: (ctx) => {
      const evidence = find(ctx, 'scim.resource-types');
      if (evidence?.fetch?.status !== 200) return undefined;
      const types = resources(evidence);
      const user = types.find((t) => t.schema === `${CORE}User`);
      if (!user) {
        return {
          severity: 'error',
          detail: `No resource type uses the core User schema. Published: ${types.map((t) => String(t.name)).join(', ') || 'none'}.`,
          evidence,
        };
      }
      const group = types.some((t) => t.schema === `${CORE}Group`);
      return {
        severity: 'pass',
        detail: `User is served at ${String(user.endpoint)}. Group resource type: ${group ? 'present' : 'absent, so group push will not work'}.`,
        evidence,
      };
    },
  },
  {
    id: 'scim.schemas.referenced',
    protocol: 'scim',
    category: 'conformance',
    title: 'Every schema a resource type references is published',
    citation: SCHEMA('7'),
    remediation: {
      'scim-server': 'Serve each referenced schema, including extensions, from /Schemas.',
    },
    run: (ctx) => {
      const types = find(ctx, 'scim.resource-types');
      const schemas = find(ctx, 'scim.schemas');
      if (types?.fetch?.status !== 200 || schemas?.fetch?.status !== 200) return undefined;
      const published = new Set(resources(schemas).map((s) => String(s.id)));
      const referenced = resources(types).flatMap((t) => [
        String(t.schema),
        ...objects(t.schemaExtensions).map((x) => String(x.schema)),
      ]);
      const missing = [...new Set(referenced)].filter((urn) => !published.has(urn));
      return missing.length
        ? {
            severity: 'warn',
            detail: `Referenced by a resource type but absent from /Schemas: ${missing.join(', ')}.`,
            evidence: schemas,
          }
        : {
            severity: 'pass',
            detail: `All ${new Set(referenced).size} referenced schemas are published.`,
            evidence: schemas,
          };
    },
  },
  {
    id: 'scim.schemas.user-name',
    protocol: 'scim',
    category: 'conformance',
    title: 'User schema defines userName as required and unique',
    citation: SCHEMA('4.1.1'),
    remediation: { 'scim-server': 'Declare userName with required true and uniqueness "server".' },
    run: (ctx) => {
      const evidence = find(ctx, 'scim.schemas');
      if (evidence?.fetch?.status !== 200) return undefined;
      const user = resources(evidence).find((s) => s.id === `${CORE}User`);
      if (!user) return undefined;
      const attr = objects(user.attributes).find((a) => a.name === 'userName');
      if (!attr)
        return {
          severity: 'error',
          detail: 'The User schema has no userName attribute.',
          evidence,
        };
      return attr.required === true && attr.uniqueness === 'server'
        ? { severity: 'pass', detail: 'userName is required with server uniqueness.', evidence }
        : {
            severity: 'warn',
            detail: `userName has required ${String(attr.required)} and uniqueness "${String(attr.uniqueness)}"; the core schema defines it as required and server-unique.`,
            evidence,
          };
    },
  },
  {
    id: 'scim.schemas.enterprise-extension',
    protocol: 'scim',
    category: 'interop',
    title: 'Enterprise User extension availability',
    citation: SCHEMA('4.3'),
    remediation: {
      'scim-server':
        'Accept the enterprise extension even if most of it is ignored; default Entra ID and Okta mappings send department and manager through it.',
    },
    run: (ctx) => {
      const evidence = find(ctx, 'scim.schemas');
      if (evidence?.fetch?.status !== 200) return undefined;
      const present = resources(evidence).some((s) => s.id === ENTERPRISE);
      return {
        severity: 'info',
        detail: present
          ? 'The enterprise User extension is published.'
          : 'The enterprise User extension is not published. Default directory mappings that send manager or department will need to be removed on the client side.',
        evidence,
      };
    },
  },
];

export { KINDS as scimEvidenceKinds };
