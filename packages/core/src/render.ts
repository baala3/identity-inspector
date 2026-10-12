import type { Finding, Report, Role, Severity } from './model.js';

const MARK: Record<Severity, string> = { error: 'ERROR', warn: 'WARN', info: 'INFO', pass: 'PASS' };

const ROLE: Record<Role, string> = {
  op: 'If you run the OpenID Provider',
  rp: 'If you run the Relying Party',
  idp: 'If you run the Identity Provider',
  sp: 'If you run the Service Provider',
  'scim-server': 'If you run the SCIM server',
  'scim-client': 'If you run the SCIM client',
};

export const roleLabel = (role: Role) => ROLE[role];

export function summaryLine(report: Report): string {
  const { error, warn, info, pass } = report.summary;
  return `${error} error, ${warn} warn, ${info} info, ${pass} pass`;
}

function findingMarkdown(finding: Finding): string {
  const lines = [
    `### ${MARK[finding.severity]} \`${finding.checkId}\` - ${finding.title}`,
    '',
    finding.detail,
    '',
    `- Category: ${finding.category}`,
    `- Provenance: ${finding.provenance}`,
    `- Citation: [${finding.citation.label}](${finding.citation.url})`,
  ];
  if (finding.pointer)
    lines.push(`- Evidence: \`${finding.evidenceId}\` at \`${finding.pointer}\``);
  for (const [role, text] of Object.entries(finding.remediation) as [Role, string][]) {
    lines.push(`- ${ROLE[role]}: ${text}`);
  }
  return lines.join('\n');
}

export function toMarkdown(report: Report): string {
  const out = [
    `# ${report.target.protocol.toUpperCase()} inspection: ${report.target.input}`,
    '',
    `Evaluated at ${report.instant}.`,
    `${summaryLine(report)}.`,
    '',
    '## Evidence',
    '',
    ...report.evidence.map(
      (e) =>
        `- \`${e.id}\` (${e.provenance})${e.source ? ` from ${e.source}` : ''}${e.fetch ? `, HTTP ${e.fetch.status}` : ''}, ${e.bytes} bytes`,
    ),
    '',
    '## Flow',
    '',
    'Steps marked illustrative were not performed by this inspection.',
    '',
    ...report.flow.map(
      (s, i) =>
        `${i + 1}. ${s.from} -> ${s.to}: ${s.label} (${s.provenance})${s.endpoint ? ` - ${s.endpoint}` : ''}`,
    ),
    '',
    '## What it publishes',
    '',
    'Restated from the evidence. These are claims, not tested behaviour.',
    '',
    ...report.overview.flatMap((section) => [
      `### ${section.title}`,
      '',
      ...section.facts.map((fact) => `- ${fact.label}: ${fact.values.join(', ')}`),
      '',
    ]),
    '## Findings',
    '',
    ...report.findings.map((f) => `${findingMarkdown(f)}\n`),
  ];
  return out.join('\n');
}
