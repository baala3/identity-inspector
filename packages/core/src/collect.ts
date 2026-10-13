import { issuerOf, message } from './checks/saml-response.js';
import { looksLikeJwt, parseJwt } from './jwt.js';
import type { Evidence, EvidenceKind, Fetcher, FetchResult, Protocol, Workspace } from './model.js';
import { json, parseXml } from './parse.js';
import { decodeBase64 } from './x509.js';

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
  if (looksLikeJwt(input)) {
    const token: Evidence = {
      id: 'oidc.token',
      kind: 'oidc.token',
      provenance: 'user-supplied',
      raw: input.trim(),
    };
    // The token names its issuer, and only that URL is ever requested: the token itself stays here.
    const iss = parseJwt(token.raw).jwt?.claims.iss;
    if (typeof iss !== 'string' || !/^https?:\/\//i.test(iss)) {
      return { target: { protocol: 'oidc', input: 'pasted token' }, evidence: [token] };
    }
    const { target, evidence } = await collectOidc(iss, fetcher);
    return { target, evidence: [token, ...evidence] };
  }
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

// The root element, past any declaration, comment, or DTD. A DTD is refused later, by name.
const MESSAGE_ROOT =
  /^\s*(?:<\?[\s\S]*?\?>\s*|<!--[\s\S]*?-->\s*|<!DOCTYPE[^[>]*(?:\[[\s\S]*?\])?\s*>\s*)*<(?:[\w.-]+:)?(?:Response|Assertion)[\s>]/;
const BASE64 = /^[A-Za-z0-9+/=%\s]{100,}$/;

/**
 * The XML of a pasted SAML Response or Assertion, or nothing when the input is not one.
 * A response is usually copied from the browser as the base64 text of the SAMLResponse
 * form field, sometimes still URL-encoded, so that form is accepted as well as XML.
 */
export function samlMessage(input: string): string | undefined {
  const pasted = input.trim();
  if (MESSAGE_ROOT.test(pasted)) return pasted;
  if (!BASE64.test(pasted)) return undefined;
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(
      decodeBase64(decodeURIComponent(pasted)),
    );
    return MESSAGE_ROOT.test(decoded) ? decoded.trim() : undefined;
  } catch {
    return undefined;
  }
}

/** Metadata from wherever it was given: pasted XML, or a URL to fetch. */
async function metadataFrom(input: string, fetcher: Fetcher): Promise<Evidence> {
  return looksLikeXml(input)
    ? { id: 'saml.metadata', kind: 'saml.metadata', provenance: 'user-supplied', raw: input }
    : fetched('saml.metadata', await fetcher(asUrl(input)));
}

export async function collectSaml(
  input: string,
  fetcher: Fetcher,
  metadata?: string,
): Promise<Workspace> {
  const pasted = samlMessage(input);
  if (pasted) {
    const response: Evidence = {
      id: 'saml.response',
      kind: 'saml.response',
      provenance: 'user-supplied',
      raw: pasted,
    };
    const read = message(response);
    return {
      target: { protocol: 'saml', input: (read && issuerOf(read)) ?? 'pasted response' },
      // The response itself is never sent anywhere. Metadata is fetched only when a URL was given for it.
      evidence: metadata?.trim()
        ? [response, await metadataFrom(metadata.trim(), fetcher)]
        : [response],
    };
  }
  const evidence = await metadataFrom(input, fetcher);
  return {
    target: { protocol: 'saml', input: evidence.source ?? 'pasted metadata' },
    evidence: [evidence],
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
  /** Where the IdP metadata for a pasted SAML response is: a URL, or the XML itself. */
  samlMetadata?: string;
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
  if (protocol === 'saml') return collectSaml(input, fetcher, options.samlMetadata);
  if (protocol === 'scim') return collectScim(input, fetcher, options.scimHeaders);
  return collectOidc(input, fetcher);
}

const SAML_PATH = /saml|metadata|\.xml$/i;
const SCIM_PATH = /\/scim(\/|$)|\/(ServiceProviderConfig|ResourceTypes|Schemas)\/?$/i;

export async function detect(input: string, fetcher: Fetcher): Promise<Protocol> {
  if (looksLikeXml(input) || samlMessage(input)) return 'saml';
  if (looksLikeJwt(input)) return 'oidc';
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
