import type { Evidence, EvidenceKind, Fetcher, FetchResult, Protocol, Workspace } from './model.js';
import { json, parseXml } from './parse.js';

function fetched(kind: EvidenceKind, result: FetchResult): Evidence {
  const { url, body, ...fetch } = result;
  return { id: kind, kind, provenance: 'discovered', source: url, fetch, raw: body };
}

const WELL_KNOWN = '/.well-known/openid-configuration';

function asUrl(input: string): string {
  const trimmed = input.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

export async function collectOidc(input: string, fetcher: Fetcher): Promise<Workspace> {
  // Accept an issuer, a bare domain, or the discovery URL itself.
  const issuer = asUrl(input).replace(WELL_KNOWN, '');
  const discovery = fetched(
    'oidc.discovery',
    await fetcher(issuer.replace(/\/$/, '') + WELL_KNOWN),
  );
  const evidence = [discovery];
  const jwksUri = json(discovery)?.jwks_uri;
  if (typeof jwksUri === 'string' && URL.canParse(jwksUri)) {
    evidence.push(fetched('oidc.jwks', await fetcher(jwksUri)));
  }
  return { target: { protocol: 'oidc', input: issuer }, evidence };
}

export const looksLikeXml = (input: string) => input.trimStart().startsWith('<');

export async function collectSaml(input: string, fetcher: Fetcher): Promise<Workspace> {
  if (looksLikeXml(input)) {
    return {
      target: { protocol: 'saml', input: 'pasted metadata' },
      evidence: [
        { id: 'saml.metadata', kind: 'saml.metadata', provenance: 'user-supplied', raw: input },
      ],
    };
  }
  const url = asUrl(input);
  return {
    target: { protocol: 'saml', input: url },
    evidence: [fetched('saml.metadata', await fetcher(url))],
  };
}

export async function collectScim(
  input: string,
  fetcher: Fetcher,
  headers: Record<string, string> = {},
): Promise<Workspace> {
  const base = asUrl(input)
    .replace(/\/(ServiceProviderConfig|ResourceTypes|Schemas)\/?$/, '')
    .replace(/\/$/, '');
  const accept = { accept: 'application/scim+json, application/json', ...headers };
  const [config, types, schemas] = await Promise.all([
    fetcher(`${base}/ServiceProviderConfig`, accept),
    fetcher(`${base}/ResourceTypes`, accept),
    fetcher(`${base}/Schemas`, accept),
  ]);
  return {
    target: { protocol: 'scim', input: base },
    evidence: [
      fetched('scim.service-provider-config', config),
      fetched('scim.resource-types', types),
      fetched('scim.schemas', schemas),
    ],
  };
}

export interface CollectOptions {
  protocol?: Protocol;
  /** Sent only to SCIM endpoints. Never pass a credential through the proxy (ADR 0001). */
  scimHeaders?: Record<string, string>;
}

/** Gathers evidence for whatever the input turns out to be. */
export async function collect(
  input: string,
  fetcher: Fetcher,
  options: CollectOptions = {},
): Promise<Workspace> {
  const protocol = options.protocol ?? (await detect(input, fetcher));
  if (protocol === 'saml') return collectSaml(input, fetcher);
  if (protocol === 'scim') return collectScim(input, fetcher, options.scimHeaders);
  return collectOidc(input, fetcher);
}

const SAML_PATH = /saml|metadata|\.xml$/i;
const SCIM_PATH = /\/scim(\/|$)|\/(ServiceProviderConfig|ResourceTypes|Schemas)\/?$/i;

export async function detect(input: string, fetcher: Fetcher): Promise<Protocol> {
  if (looksLikeXml(input)) return 'saml';
  const url = asUrl(input);
  if (url.includes(WELL_KNOWN)) return 'oidc';
  const { pathname } = new URL(url);
  if (SCIM_PATH.test(pathname)) return 'scim';

  const direct = await fetcher(url);
  if (direct.status === 200 && looksLikeXml(direct.body) && parseXml(direct.body).document)
    return 'saml';
  // An unreachable host tells us nothing, so fall back on what the URL looks like.
  if (direct.status === 0 && SAML_PATH.test(pathname)) return 'saml';

  const discovery = await fetcher(url.replace(/\/$/, '') + WELL_KNOWN);
  if (discovery.status === 200) return 'oidc';

  const config = await fetcher(`${url.replace(/\/$/, '')}/ServiceProviderConfig`);
  if (config.status === 200 || config.status === 401) return 'scim';
  return 'oidc';
}
