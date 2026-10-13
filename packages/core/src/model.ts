// Vocabulary here follows CONTEXT.md at the repo root.

export type Protocol = 'oidc' | 'oauth' | 'saml' | 'scim';

export type Role = 'op' | 'rp' | 'as' | 'client' | 'idp' | 'sp' | 'scim-server' | 'scim-client';

export type Category = 'conformance' | 'security' | 'interop';

export type Severity = 'error' | 'warn' | 'info' | 'pass';

export type Provenance = 'discovered' | 'illustrative' | 'executed' | 'user-supplied';

export type EvidenceKind =
  | 'oidc.discovery'
  | 'oauth.metadata'
  | 'oidc.jwks'
  | 'oidc.token'
  | 'saml.metadata'
  | 'saml.response'
  | 'scim.service-provider-config'
  | 'scim.resource-types'
  | 'scim.schemas';

export interface FetchResult {
  url: string;
  /** 0 when the request never produced a response. */
  status: number;
  headers: Record<string, string>;
  body: string;
  error?: string;
}

export type Fetcher = (url: string, headers?: Record<string, string>) => Promise<FetchResult>;

export interface Evidence {
  id: string;
  kind: EvidenceKind;
  provenance: Extract<Provenance, 'discovered' | 'user-supplied'>;
  /** Where it was fetched from, absent for pasted evidence. */
  source?: string;
  fetch?: Omit<FetchResult, 'body' | 'url'>;
  raw: string;
}

export interface Target {
  protocol: Protocol;
  /** What the user asked to inspect, normalized to a URL where it was one. */
  input: string;
}

export interface Workspace {
  target: Target;
  evidence: Evidence[];
}

export interface Citation {
  label: string;
  url: string;
}

export interface Finding {
  checkId: string;
  title: string;
  category: Category;
  severity: Severity;
  provenance: Provenance;
  detail: string;
  citation: Citation;
  remediation: Partial<Record<Role, string>>;
  /** The evidence the verdict rests on, and where in it. */
  evidenceId?: string;
  pointer?: string;
}

export interface Outcome {
  severity: Severity;
  detail: string;
  evidence?: Evidence;
  pointer?: string;
  /** Replaces the check's remediation when this outcome calls for different advice. */
  remediation?: Partial<Record<Role, string>>;
}

export interface CheckContext {
  workspace: Workspace;
  /** The evaluation instant. */
  instant: Date;
}

export interface Check {
  id: string;
  /** More than one where the same rule binds targets of several protocols. */
  protocol: Protocol | readonly Protocol[];
  category: Category;
  title: string;
  citation: Citation;
  remediation?: Partial<Record<Role, string>>;
  /**
   * Returns nothing when the check does not apply to this workspace.
   * Only a check that does signature math needs to be asynchronous.
   */
  run(
    ctx: CheckContext,
  ): Outcome | Outcome[] | undefined | Promise<Outcome | Outcome[] | undefined>;
}

export interface FlowStep {
  id: string;
  from: string;
  to: string;
  label: string;
  provenance: Provenance;
  /** The endpoint this step would hit, when the target published one. */
  endpoint?: string;
  /** Check id prefixes whose findings concern this step. */
  concerns: string[];
}

export interface Fact {
  label: string;
  values: string[];
  style: 'text' | 'link' | 'chips';
}

export interface OverviewSection {
  id: string;
  title: string;
  facts: Fact[];
}

export interface Report {
  target: Target;
  instant: string;
  evidence: Array<Omit<Evidence, 'raw'> & { bytes: number }>;
  findings: Finding[];
  flow: FlowStep[];
  /** What the evidence states, with no verdict attached. */
  overview: OverviewSection[];
  summary: Record<Severity, number>;
}
