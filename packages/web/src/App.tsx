import {
  type Finding,
  KIND_LABEL,
  kindOf,
  looksLikeJwt,
  looksLikeXml,
  type OverviewSection,
  type Protocol,
  type Provenance,
  parseJwt,
  type Report,
  type Role,
  roleLabel,
  type Severity,
  samlMessage,
  toMarkdown,
} from '@identity-inspector/core';
import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { concerns, Flow } from './Flow.js';
import type { InspectRequest, InspectResponse } from './protocol.js';

const PROXY = import.meta.env.VITE_PROXY_URL ?? '/api';

const EXAMPLES = [
  ['OAUTH', 'mcp.notion.com'],
  ['OIDC', 'https://login.microsoftonline.com/common/v2.0'],
  ['SAML', 'https://mocksaml.com/api/saml/metadata'],
  ['SCIM', 'https://api.slack.com/scim/v2'],
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

/** Pasted material is read in this browser and never becomes part of a link. */
const isResponse = (input: string) => samlMessage(input) !== undefined;
const isPasted = (input: string) => looksLikeXml(input) || looksLikeJwt(input) || isResponse(input);

function download(name: string, type: string, text: string) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([text], { type }));
  link.download = name;
  link.click();
  URL.revokeObjectURL(link.href);
}

/** Indented JSON with its member names set apart. */
function members(value: unknown, key: string): ReactNode[] {
  const json = JSON.stringify(value, null, 2);
  const parts: ReactNode[] = [];
  let at = 0;
  for (const match of json.matchAll(/"(?:\\.|[^"\\])*"/g)) {
    if (json[match.index + match[0].length] !== ':') continue;
    parts.push(json.slice(at, match.index), <b key={`${key} ${match.index}`}>{match[0]}</b>);
    at = match.index + match[0].length;
  }
  parts.push(json.slice(at));
  return parts;
}

/** What a pasted token is taken for, or nothing when the text is not a readable token. */
function tokenKind(text: string | undefined): string | undefined {
  const { jwt } = text && looksLikeJwt(text) ? parseJwt(text) : {};
  return jwt && KIND_LABEL[kindOf(jwt).kind];
}

/** Evidence as it was received: JSON indented, and a token opened into its header and payload. */
function Raw({ text }: { text: string }) {
  const { jwt } = looksLikeJwt(text) ? parseJwt(text) : {};
  if (jwt) {
    return (
      <pre>
        {members(jwt.header, 'header')}
        {'\n\n'}
        {members(jwt.claims, 'claims')}
      </pre>
    );
  }
  try {
    return <pre>{members(JSON.parse(text), 'json')}</pre>;
  } catch {
    return <pre>{text}</pre>;
  }
}

function FindingCard({ finding }: { finding: Finding }) {
  const remediation = Object.entries(finding.remediation) as [Role, string][];
  return (
    <li className={`finding ${finding.severity}`}>
      <div className="finding-head">
        <h3>{finding.title}</h3>
        <span className="notch">
          <span className={`badge ${finding.severity}`}>{finding.severity}</span>
        </span>
      </div>
      <div className="finding-body">
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
  const [metadata, setMetadata] = useState('');
  const [status, setStatus] = useState<Status>({ state: 'idle' });
  const [result, setResult] = useState<Result>();
  const [only, setOnly] = useState<Severity>();
  const [step, setStep] = useState<string>();
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === 'dark');
  const [view, setView] = useState<'findings' | 'overview'>('findings');
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

  const inspect = useCallback(
    (target: string, as: Protocol | 'auto', when: string, idpMetadata = '') => {
      const trimmed = target.trim();
      if (!trimmed) return;
      const instant = when ? new Date(when) : undefined;
      const request: InspectRequest = {
        id: ++latest.current,
        input: trimmed,
        proxy: PROXY,
        ...(as !== 'auto' && { protocol: as }),
        ...(isResponse(trimmed) && idpMetadata.trim() && { metadata: idpMetadata.trim() }),
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
    },
    [],
  );

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

  const toggleTheme = () => {
    const next = !dark;
    setDark(next);
    if (next) document.documentElement.dataset.theme = 'dark';
    else delete document.documentElement.dataset.theme;
    try {
      localStorage.setItem('theme', next ? 'dark' : 'light');
    } catch {
      // Storage can be unavailable; the choice then lasts for this visit only.
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    inspect(input, protocol, at, metadata);
  };

  const report = result?.report;
  const selected = report?.flow.find((s) => s.id === step);
  const visible =
    report?.findings.filter(
      (f) => (!only || f.severity === only) && (!selected || concerns(selected, f)),
    ) ?? [];
  const pastedResponse = isResponse(input);
  // Metadata is the only XML that is not a response; both need room and keep Enter for new lines.
  const pastedXml = looksLikeXml(input) || pastedResponse;
  const pastedToken = looksLikeJwt(input);
  const pastedKind = tokenKind(input) ?? 'token';
  const inspectedKind =
    tokenKind(result?.raw['oidc.token']) ?? (result?.raw['saml.response'] ? 'response' : undefined);

  return (
    <div className="page">
      <header className="masthead">
        <a className="brand" href={import.meta.env.BASE_URL} aria-label="Identity Inspector home">
          <svg className="mark" viewBox="0 0 40 40" aria-hidden="true">
            <rect width="40" height="40" rx="9" />
            <circle cx="18" cy="18" r="7" />
            <path d="m23.5 23.5 6.5 6.5" />
          </svg>
          <h1>Identity Inspector</h1>
        </a>
        <div className="bar">
          <p>
            Diagnostics for OIDC, OAuth 2.0, SAML SSO, and SCIM that say what was verified and what
            was only read.
          </p>
          <button
            type="button"
            className="theme"
            aria-pressed={dark}
            aria-label="Dark theme"
            title={dark ? 'Switch to light theme' : 'Switch to dark theme'}
            onClick={toggleTheme}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              {dark ? (
                <>
                  <circle cx="12" cy="12" r="4" />
                  <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4" />
                </>
              ) : (
                <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" />
              )}
            </svg>
          </button>
        </div>
      </header>

      <form className="target" onSubmit={submit}>
        <label htmlFor="target">Target</label>
        <textarea
          id="target"
          value={input}
          rows={pastedXml ? 8 : pastedToken ? 5 : 1}
          spellCheck={false}
          placeholder="OIDC issuer or token, OAuth server, SAML metadata or response, or SCIM base URL"
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey && !pastedXml) {
              event.preventDefault();
              inspect(input, protocol, at, metadata);
            }
          }}
        />
        {pastedResponse && (
          <>
            <label htmlFor="metadata">IdP metadata (optional)</label>
            <textarea
              id="metadata"
              value={metadata}
              rows={looksLikeXml(metadata) ? 6 : 1}
              spellCheck={false}
              placeholder="Metadata URL or XML. It is what shows who signed the response."
              onChange={(event) => setMetadata(event.target.value)}
            />
          </>
        )}
        <div className="controls">
          <fieldset className="segmented">
            <legend>Protocol</legend>
            {(['auto', 'oauth', 'oidc', 'saml', 'scim'] as const).map((option) => (
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
            <span className="ico" aria-hidden="true">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M17.25 8.25 21 12m0 0-3.75 3.75M21 12H3" />
              </svg>
            </span>
            <span>{status.state === 'loading' ? 'Inspecting…' : 'Inspect'}</span>
          </button>
        </div>
        <p className="trust">
          {pastedResponse
            ? 'The response is read in this browser and is not sent anywhere. Metadata given as a URL is fetched by the proxy; pasted metadata stays here too.'
            : pastedXml
              ? 'Pasted XML is parsed in this browser and is not sent anywhere.'
              : pastedToken
                ? `This ${pastedKind} is read in this browser and is not sent anywhere. Only the issuer it names is asked for its public documents.`
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
                {inspectedKind && <span className="tag solid kind">{inspectedKind}</span>}{' '}
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
                    <Raw text={result.raw[evidence.id] || evidence.fetch?.error || '(empty)'} />
                  </details>
                ))}
              </section>
            </aside>

            <section className="findings">
              <div className="tabs" role="tablist">
                <button
                  type="button"
                  role="tab"
                  aria-selected={view === 'findings'}
                  onClick={() => setView('findings')}
                >
                  Findings <span>{report.findings.length - report.summary.pass} to review</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={view === 'overview'}
                  onClick={() => setView('overview')}
                >
                  What it publishes
                </button>
              </div>
              {view === 'overview' && (
                <Overview
                  sections={report.overview}
                  evidence={report.evidence}
                  unseen={report.unseen}
                />
              )}
              {view === 'findings' && (
                <div className="filters">
                  {SEVERITIES.map((severity) => (
                    <button
                      key={severity}
                      type="button"
                      className={`chip ${severity}`}
                      aria-pressed={only === severity}
                      title={only === severity ? 'Show every severity' : `Show only ${severity}`}
                      onClick={() => setOnly(only === severity ? undefined : severity)}
                    >
                      <b>{report.summary[severity]}</b> {severity}
                    </button>
                  ))}
                  {selected && (
                    <button type="button" className="clear" onClick={() => setStep(undefined)}>
                      Step {report.flow.indexOf(selected) + 1} only · clear
                    </button>
                  )}
                </div>
              )}
              {view !== 'findings' ? null : visible.length ? (
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

function Overview({
  sections,
  evidence,
  unseen,
}: {
  sections: OverviewSection[];
  evidence: Report['evidence'];
  unseen: string[];
}) {
  // A document that could not be fetched leaves its sections out, which must not pass unnoticed.
  const unread = evidence.filter((e) => e.fetch && e.fetch.status !== 200);
  const missing = unread.length > 0 && (
    <p className="unread" role="note">
      Not shown, because it could not be read:{' '}
      {unread.map((e) => `${e.source} (${e.fetch?.error ?? `HTTP ${e.fetch?.status}`})`).join(', ')}
      . The Findings tab has the details.
    </p>
  );
  if (!sections.length) {
    return (
      <div className="overview">
        <p className="muted none">Nothing readable was published, so there is nothing to show.</p>
        {missing}
      </div>
    );
  }
  return (
    <div className="overview">
      <p className="muted">
        Restated from the evidence. These are the target's own claims, not tested behaviour.
      </p>
      {missing}
      {sections.map((section) => (
        <section key={section.id} className="card">
          <h2>{section.title}</h2>
          <dl>
            {section.facts.map((fact, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: labels repeat (several certificates share a subject) and the list is static
              <div key={`${fact.label} ${index}`}>
                <dt>{fact.label}</dt>
                <dd>
                  {fact.style === 'chips' ? (
                    <ul className="values">
                      {fact.values.map((value, position) => (
                        // biome-ignore lint/suspicious/noArrayIndexKey: values may repeat and the list is static
                        <li key={`${value} ${position}`}>
                          <code>{value}</code>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <code>{fact.values.join(', ')}</code>
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
      {unseen.length > 0 && (
        <section className="card unseen">
          <h2>Not visible in what it publishes</h2>
          <p className="muted">
            No published document can show these. Only a request to the target can.
          </p>
          <ul>
            {unseen.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      )}
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
