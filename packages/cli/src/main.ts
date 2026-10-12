#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { parseArgs, styleText } from 'node:util';
import {
  collect,
  evaluate,
  type Fetcher,
  type Protocol,
  type Report,
  type Role,
  roleLabel,
  type Severity,
  summaryLine,
  toMarkdown,
} from '@identity-inspector/core';

const USAGE = `Usage: idi inspect <target> [options]

<target> is an OIDC issuer or domain, a SAML metadata URL or XML file,
or a SCIM base URL.

Options:
  --protocol <oidc|saml|scim>   Skip detection
  --format <text|json|md>       Output format (default text)
  --fail-on <error|warn|never>  Exit 1 at this severity or worse (default error)
  --at <ISO date>               Evaluation instant (default now)
  --all                         Also list passing checks in text output

Environment:
  SCIM_TOKEN                    Bearer token sent to SCIM endpoints only
`;

const fetcher: Fetcher = async (url, headers = {}) => {
  try {
    const response = await fetch(url, {
      headers: { 'user-agent': 'identity-inspector', ...headers },
      redirect: 'follow',
      signal: AbortSignal.timeout(15_000),
    });
    return {
      url,
      status: response.status,
      headers: Object.fromEntries(response.headers),
      body: await response.text(),
    };
  } catch (error) {
    const cause =
      error instanceof Error
        ? ((error.cause as Error | undefined)?.message ?? error.message)
        : String(error);
    return { url, status: 0, headers: {}, body: '', error: cause };
  }
};

const COLOR: Record<Severity, Parameters<typeof styleText>[0]> = {
  error: 'red',
  warn: 'yellow',
  info: 'cyan',
  pass: 'green',
};

function toText(report: Report, all: boolean): string {
  const out = [
    styleText('bold', `${report.target.protocol.toUpperCase()} ${report.target.input}`),
    styleText('dim', `evaluated at ${report.instant}`),
    '',
  ];
  for (const finding of report.findings) {
    if (finding.severity === 'pass' && !all) continue;
    out.push(
      `${styleText(COLOR[finding.severity], finding.severity.toUpperCase().padEnd(5))} ${finding.title}`,
      styleText('dim', `      ${finding.checkId} | ${finding.category} | ${finding.provenance}`),
      `      ${finding.detail}`,
    );
    for (const [role, text] of Object.entries(finding.remediation) as [Role, string][]) {
      out.push(`      ${styleText('dim', `${roleLabel(role)}:`)} ${text}`);
    }
    out.push(styleText('dim', `      ${finding.citation.label}`), '');
  }
  out.push(styleText('bold', 'Flow'));
  for (const step of report.flow) {
    out.push(
      `  ${step.from} -> ${step.to}: ${step.label} ${styleText('dim', `[${step.provenance}]`)}${step.endpoint ? styleText('dim', ` ${step.endpoint}`) : ''}`,
    );
  }
  out.push('', summaryLine(report));
  if (!all && report.summary.pass)
    out.push(styleText('dim', 'Passing checks hidden; use --all to list them.'));
  return out.join('\n');
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      protocol: { type: 'string' },
      format: { type: 'string', default: 'text' },
      'fail-on': { type: 'string', default: 'error' },
      at: { type: 'string' },
      all: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  const [command, target] = positionals;
  if (values.help || command !== 'inspect' || !target) {
    process.stderr.write(USAGE);
    return values.help ? 0 : 2;
  }
  if (values.protocol && !['oidc', 'saml', 'scim'].includes(values.protocol)) {
    process.stderr.write(`Unknown protocol "${values.protocol}".\n`);
    return 2;
  }
  const instant = values.at ? new Date(values.at) : new Date();
  if (Number.isNaN(instant.getTime())) {
    process.stderr.write(`--at "${values.at}" is not a date.\n`);
    return 2;
  }

  const input = existsSync(target) ? readFileSync(target, 'utf8') : target;
  const token = process.env.SCIM_TOKEN;
  const workspace = await collect(input, fetcher, {
    ...(values.protocol && { protocol: values.protocol as Protocol }),
    ...(token && { scimHeaders: { authorization: `Bearer ${token}` } }),
  });
  const report = evaluate(workspace, instant);

  const rendered =
    values.format === 'json'
      ? JSON.stringify(report, null, 2)
      : values.format === 'md'
        ? toMarkdown(report)
        : toText(report, values.all);
  process.stdout.write(`${rendered}\n`);

  const failed =
    values['fail-on'] === 'never'
      ? false
      : report.summary.error > 0 || (values['fail-on'] === 'warn' && report.summary.warn > 0);
  return failed ? 1 : 0;
}

process.exitCode = await main();
