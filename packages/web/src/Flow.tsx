import type { Finding, FlowStep, Severity } from '@identity-inspector/core';

const LANE_GAP = 160;
const ROW = 62;
const TOP = 46;
const PAD = 60;
const GUTTER = 24;

// The user agent sits on the left and the party that issues identity on the right.
const LANE_ORDER = [
  'Browser',
  'SCIM client',
  'RP',
  'Client',
  'API',
  'SP',
  'OP',
  'AS',
  'IdP',
  'SCIM server',
];

const WORST: Severity[] = ['error', 'warn', 'info', 'pass'];

export function concerns(step: FlowStep, finding: Finding): boolean {
  return step.concerns.some((prefix) => finding.checkId.startsWith(prefix));
}

interface Props {
  steps: FlowStep[];
  findings: Finding[];
  selected: string | undefined;
  onSelect(id: string | undefined): void;
}

/** A sequence diagram in which each step shows how it was obtained and what was found about it. */
export function Flow({ steps, findings, selected, onSelect }: Props) {
  const lanes = [...new Set(steps.flatMap((s) => [s.from, s.to]))].sort(
    (a, b) => LANE_ORDER.indexOf(a) - LANE_ORDER.indexOf(b),
  );
  const x = (name: string) => PAD + lanes.indexOf(name) * LANE_GAP;
  // The gutter on the right holds the severity marker clear of any label.
  const width = PAD * 2 + (lanes.length - 1) * LANE_GAP + GUTTER;
  const height = TOP + steps.length * ROW + 16;

  return (
    <svg className="flow" viewBox={`0 0 ${width} ${height}`}>
      <title>Protocol flow</title>
      <defs>
        <marker
          id="arrow"
          viewBox="0 0 10 10"
          refX="9"
          refY="5"
          markerWidth="7"
          markerHeight="7"
          orient="auto-start-reverse"
        >
          <path d="M0 0 10 5 0 10z" fill="context-stroke" />
        </marker>
      </defs>
      {lanes.map((lane) => (
        <g key={lane}>
          <line className="lane" x1={x(lane)} x2={x(lane)} y1={30} y2={height - 6} />
          <text className="lane-name" x={x(lane)} y={18} textAnchor="middle">
            {lane}
          </text>
        </g>
      ))}
      {steps.map((step, index) => {
        const y = TOP + index * ROW + 26;
        const about = findings.filter((f) => concerns(step, f));
        const worst = WORST.find((s) => about.some((f) => f.severity === s));
        const loop = step.from === step.to;
        const from = x(step.from);
        const to = x(step.to);
        const mid = loop ? from + 60 : (from + to) / 2;
        const path = loop
          ? `M${from} ${y - 4}h44v16H${from + 4}`
          : `M${from} ${y}H${to + (to > from ? -3 : 3)}`;
        const active = selected === step.id;
        return (
          // biome-ignore lint/a11y/useSemanticElements: an SVG group cannot be a button element
          <g
            key={step.id}
            className={`step ${step.provenance}${active ? ' active' : ''}`}
            role="button"
            tabIndex={0}
            aria-pressed={active}
            aria-label={`${step.label}, ${step.provenance}, ${about.length} findings`}
            onClick={() => onSelect(active ? undefined : step.id)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                onSelect(active ? undefined : step.id);
              }
            }}
          >
            <rect className="hit" x={8} y={y - 28} width={width - 16} height={ROW - 6} rx={6} />
            <text
              className="step-label"
              x={loop ? (width - GUTTER) / 2 : mid}
              y={y - 12}
              textAnchor="middle"
            >
              <tspan className="index">{index + 1}</tspan> {step.label}
            </text>
            <path className="wire" d={path} markerEnd="url(#arrow)" />
            <text
              className="step-meta"
              x={loop ? from + 56 : mid}
              y={loop ? y + 8 : y + 15}
              textAnchor={loop ? 'start' : 'middle'}
            >
              {step.provenance}
              {about.length > 0 && ` · ${about.length} finding${about.length === 1 ? '' : 's'}`}
            </text>
            {worst && worst !== 'pass' && (
              <circle className={`dot ${worst}`} cx={width - 20} cy={y - 2} r={5} />
            )}
          </g>
        );
      })}
    </svg>
  );
}
