import {
  type Finding,
  type Protocol,
  type Provenance,
  type Report,
  type Role,
  roleLabel,
  type Severity,
  toMarkdown,
} from '@identity-inspector/core';
import { type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { concerns, Flow } from './Flow.js';
import type { InspectRequest, InspectResponse } from './protocol.js';

const PROXY = import.meta.env.VITE_PROXY_URL ?? '/api';

const EXAMPLES = [
  ['OIDC', 'accounts.google.com'],
  ['OIDC', 'https://login.microsoftonline.com/common/v2.0'],
  ['SAML', 'https://mocksaml.com/api/saml/metadata'],
] as const;

const SEVERITIES: Severity[] = ['error', 'warn', 'info', 'pass'];

const PROVENANCE: Record<Provenance, string> = {
  discovered: 'Read from a document the target published',
  'user-supplied': 'Pasted by you, parsed in this browser',
  executed: 'A request this tool actually made',
  illustrative: 'Shown for explanation, never performed',
};

type Status = { state: 'idle' } | { state: 'loading' } | { state: 'error'; message: string };

interface Result {
  report: Report;
  raw: Record<string, string>;
}

const isPasted = (input: string) => input.trimStart().startsWith('<');

function download(name: string, type: string, text: string) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

function pretty(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

function FindingCard({ finding }: { finding: Finding }) {
  const remediation = Object.entries(finding.remediation) as [Role, string][];
  return (
    <li className={`finding ${finding.severity}`}>
      <div className="finding-head">
        <span className={`badge ${finding.severity}`}>{finding.severity}</span>
        <h3>{finding.title}</h3>
      </div>
      <p className="detail">{finding.detail}</p>
      {remediation.length > 0 && (
        <dl className="remediation">
          {remediation.map(([role, text]) => (
            <div key={role}>
              <dt>{roleLabel(role)}</dt>
              <dd>{text}</dd>
            </div>
          ))}
        </dl>
      )}
      <div className="finding-meta">
        <code>{finding.checkId}</code>
        <span className="tag">{finding.category}</span>
        <span
          className={`tag provenance ${finding.provenance}`}
          title={PROVENANCE[finding.provenance]}
        >
          {finding.provenance}
        </span>
        {finding.pointer && <code className="pointer">{finding.pointer}</code>}
        <a href={finding.citation.url} target="_blank" rel="noreferrer">
          {finding.citation.label}
        </a>
      </div>
    </li>
  );
}

export function App() {
  const params = useMemo(() => new URLSearchParams(location.search), []);
  const [input, setInput] = useState(params.get('target') ?? '');
  const [protocol, setProtocol] = useState<Protocol | 'auto'>(
    (params.get('protocol') as Protocol | null) ?? 'auto',
  );
  const [at, setAt] = useState(params.get('at') ?? '');
  const [status, setStatus] = useState<Status>({ state: 'idle' });
  const [result, setResult] = useState<Result>();
  const [shown, setShown] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [step, setStep] = useState<string>();
  const worker = useRef<Worker>(undefined);
  const latest = useRef(0);

  useEffect(() => {
    const instance = new Worker(new URL('./engine.worker.ts', import.meta.url), { type: 'module' });
    instance.onmessage = ({ data }: MessageEvent<InspectResponse>) => {
      if (data.id !== latest.current) return;
      if ('error' in data) {
        setStatus({ state: 'error', message: data.error });
      } else {
        setResult(data);
        setStep(undefined);
        setStatus({ state: 'idle' });
      }
    };
    worker.current = instance;
    return () => instance.terminate();
  }, []);

  const inspect = useCallback((target: string, as: Protocol | 'auto', when: string) => {
    const trimmed = target.trim();
    if (!trimmed) return;
    const instant = when ? new Date(when) : undefined;
    const request: InspectRequest = {
      id: ++latest.current,
      input: trimmed,
      proxy: PROXY,
      ...(as !== 'auto' && { protocol: as }),
      ...(instant && !Number.isNaN(instant.getTime()) && { at: instant.toISOString() }),
    };
    setStatus({ state: 'loading' });
    worker.current?.postMessage(request);

    // Only a public target makes a shareable link; pasted material stays out of the URL.
    const link = new URLSearchParams();
    if (!isPasted(trimmed)) {
      link.set('target', trimmed);
      if (as !== 'auto') link.set('protocol', as);
      if (when) link.set('at', when);
    }
    history.replaceState(null, '', link.size ? `?${link}` : location.pathname);
  }, []);

  // A link that names a target runs it on arrival.
  useEffect(() => {
    const target = params.get('target');
    if (target) {
      inspect(
        target,
        (params.get('protocol') as Protocol | null) ?? 'auto',
        params.get('at') ?? '',
      );
    }
  }, [inspect, params]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    inspect(input, protocol, at);
  };

  const report = result?.report;
  const selected = report?.flow.find((s) => s.id === step);
  const visible =
    report?.findings.filter((f) => shown.has(f.severity) && (!selected || concerns(selected, f))) ??
    [];
  const pasted = isPasted(input);

  return (
    <div className="page">
      <header className="masthead">
        <h1>Identity Inspector</h1>
        <p>
          Diagnostics for OIDC, SAML SSO, and SCIM that say what was verified and what was only
          read.
        </p>
      </header>

      <form className="target" onSubmit={submit}>
        <label htmlFor="target">Target</label>
        <textarea
          id="target"
          value={input}
          rows={pasted ? 8 : 1}
          spellCheck={false}
          placeholder="OIDC issuer or domain, SAML metadata URL or XML, or SCIM base URL"
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey && !pasted) {
              event.preventDefault();
              inspect(input, protocol, at);
            }
          }}
        />
        <div className="controls">
          <fieldset className="segmented">
            <legend>Protocol</legend>
            {(['auto', 'oidc', 'saml', 'scim'] as const).map((option) => (
              <label key={option}>
                <input
                  type="radio"
                  name="protocol"
                  checked={protocol === option}
                  onChange={() => setProtocol(option)}
                />
                <span>{option === 'auto' ? 'Detect' : option.toUpperCase()}</span>
              </label>
            ))}
          </fieldset>
          <label className="as-of">
            <span>Evaluate as of</span>
            <input
              type="datetime-local"
              value={at}
              onChange={(event) => setAt(event.target.value)}
            />
          </label>
          <button type="submit" disabled={!input.trim() || status.state === 'loading'}>
            {status.state === 'loading' ? 'Inspecting…' : 'Inspect'}
          </button>
        </div>
        <p className="trust">
          {pasted
            ? 'Pasted XML is parsed in this browser and is not sent anywhere.'
            : 'URLs are fetched by a proxy that accepts a URL and nothing else. Credentials are never requested here.'}
        </p>
      </form>

      {status.state === 'error' && (
        <p className="failure" role="alert">
          Inspection failed: {status.message}
        </p>
      )}

      {!report && status.state !== 'loading' && (
        <section className="empty">
          <div>
            <h2>Try a public target</h2>
            <ul className="examples">
              {EXAMPLES.map(([kind, target]) => (
                <li key={target}>
                  <button
                    type="button"
                    onClick={() => {
                      setInput(target);
                      inspect(target, protocol, at);
                    }}
                  >
                    <span className="tag">{kind}</span>
                    <code>{target}</code>
                  </button>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h2>Every claim says where it came from</h2>
            <Legend />
          </div>
        </section>
      )}

      {report && (
        <main className={status.state === 'loading' ? 'results stale' : 'results'}>
          <div className="results-head">
            <div>
              <h2>
                <span className="tag solid">{report.target.protocol.toUpperCase()}</span>{' '}
                {report.target.input}
              </h2>
              <p className="muted">Evaluated as of {new Date(report.instant).toLocaleString()}</p>
            </div>
            <div className="exports">
              <button
                type="button"
                onClick={() =>
                  download('report.json', 'application/json', JSON.stringify(report, null, 2))
                }
              >
                JSON
              </button>
              <button
                type="button"
                onClick={() => download('report.md', 'text/markdown', toMarkdown(report))}
              >
                Markdown
              </button>
            </div>
          </div>

          <div className="columns">
            <aside>
              <section className="card">
                <h2>Flow</h2>
                <Flow
                  steps={report.flow}
                  findings={report.findings}
                  selected={step}
                  onSelect={setStep}
                />
                {selected ? (
                  <p className="step-detail">
                    <strong>{selected.label}.</strong> {PROVENANCE[selected.provenance]}.
                    {selected.endpoint && (
                      <>
                        {' '}
                        Endpoint: <code>{selected.endpoint}</code>
                      </>
                    )}
                  </p>
                ) : (
                  <p className="step-detail muted">
                    Select a step to see only the findings about it.
                  </p>
                )}
                <Legend />
              </section>

              <section className="card">
                <h2>Evidence</h2>
                {report.evidence.map((evidence) => (
                  <details key={evidence.id} className="evidence">
                    <summary>
                      <code>{evidence.id}</code>
                      <span className={`tag provenance ${evidence.provenance}`}>
                        {evidence.provenance}
                      </span>
                      <span className="muted">
                        {evidence.fetch ? `HTTP ${evidence.fetch.status || 'failed'} · ` : ''}
                        {evidence.bytes.toLocaleString()} bytes
                      </span>
                    </summary>
                    {evidence.source && <p className="muted source">{evidence.source}</p>}
                    <pre>
                      {pretty(result.raw[evidence.id] ?? '') || evidence.fetch?.error || '(empty)'}
                    </pre>
                  </details>
                ))}
              </section>
            </aside>

            <section className="findings">
              <div className="filters">
                {SEVERITIES.map((severity) => (
                  <label key={severity} className={`chip ${severity}`}>
                    <input
                      type="checkbox"
                      checked={shown.has(severity)}
                      onChange={() => {
                        const next = new Set(shown);
                        if (!next.delete(severity)) next.add(severity);
                        setShown(next);
                      }}
                    />
                    <span>
                      <b>{report.summary[severity]}</b> {severity}
                    </span>
                  </label>
                ))}
                {selected && (
                  <button type="button" className="clear" onClick={() => setStep(undefined)}>
                    Step {report.flow.indexOf(selected) + 1} only · clear
                  </button>
                )}
              </div>
              {visible.length ? (
                <ul>
                  {visible.map((finding, index) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: a check may emit several findings and the list is never reordered in place
                    <FindingCard key={`${finding.checkId} ${index}`} finding={finding} />
                  ))}
                </ul>
              ) : (
                <p className="muted none">No findings match the current filters.</p>
              )}
            </section>
          </div>
        </main>
      )}

      <footer>
        This inspection reads published documents only. It does not log in, exchange tokens, or
        verify signatures yet.
      </footer>
    </div>
  );
}

function Legend() {
  return (
    <dl className="legend">
      {(Object.entries(PROVENANCE) as [Provenance, string][]).map(([name, meaning]) => (
        <div key={name}>
          <dt>
            <span className={`tag provenance ${name}`}>{name}</span>
          </dt>
          <dd>{meaning}</dd>
        </div>
      ))}
    </dl>
  );
}
