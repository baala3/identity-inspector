import { oidcChecks } from './checks/oidc.js';
import { samlChecks } from './checks/saml.js';
import { scimChecks } from './checks/scim.js';
import { flowFor } from './flow.js';
import type { Check, Finding, Report, Severity, Workspace } from './model.js';
import { overviewFor } from './overview.js';

export const checks: readonly Check[] = [...oidcChecks, ...samlChecks, ...scimChecks];

const ORDER: Record<Severity, number> = { error: 0, warn: 1, info: 2, pass: 3 };

/** Turns a workspace into a report, judged at the evaluation instant. */
export function evaluate(workspace: Workspace, instant: Date = new Date()): Report {
  const findings: Finding[] = [];
  for (const check of checks) {
    if (check.protocol !== workspace.target.protocol) continue;
    const result = check.run({ workspace, instant });
    for (const outcome of result === undefined ? [] : [result].flat()) {
      findings.push({
        checkId: check.id,
        title: check.title,
        category: check.category,
        severity: outcome.severity,
        // A verdict is only as strong as the evidence under it.
        provenance: outcome.evidence?.provenance ?? 'user-supplied',
        detail: outcome.detail,
        citation: check.citation,
        remediation:
          outcome.severity === 'pass' ? {} : (outcome.remediation ?? check.remediation ?? {}),
        ...(outcome.evidence && { evidenceId: outcome.evidence.id }),
        ...(outcome.pointer && { pointer: outcome.pointer }),
      });
    }
  }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);

  const summary: Record<Severity, number> = { error: 0, warn: 0, info: 0, pass: 0 };
  for (const finding of findings) summary[finding.severity]++;

  return {
    target: workspace.target,
    instant: instant.toISOString(),
    evidence: workspace.evidence.map(({ raw, ...rest }) => ({ ...rest, bytes: raw.length })),
    findings,
    flow: flowFor(workspace),
    overview: overviewFor(workspace),
    summary,
  };
}
