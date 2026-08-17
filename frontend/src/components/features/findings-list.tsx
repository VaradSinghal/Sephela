'use client';

import { useMemo, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { SeverityBadge } from '@/components/ui/badge';
import { EmptyState } from '@/components/ui/feedback';
import type { Finding } from '@/lib/api/types';
import { cn } from '@/lib/utils';

// Worst first. Findings arrive in insertion order, which is engine order — not
// an order any analyst wants to read.
const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_FILTERS = ['critical', 'high', 'medium', 'low', 'info'] as const;

function rank(finding: Finding): number {
  return SEVERITY_RANK[String(finding.severity)] ?? 99;
}

function confidenceLabel(value: number | null | undefined): string {
  if (value === null || value === undefined) return 'unstated';
  if (value >= 0.95) return 'very high';
  if (value >= 0.75) return 'high';
  if (value >= 0.45) return 'medium';
  return 'low';
}

/**
 * Findings ranked by severity, each expandable to the evidence behind it.
 *
 * The expansion is the product. A finding without its provenance is an assertion;
 * with it, an analyst can check the claim and a regulator can be shown why the
 * platform said what it said.
 */
export function FindingsList({ findings }: { findings: Finding[] }) {
  const [severity, setSeverity] = useState<string | null>(null);

  const counts = useMemo(() => {
    const out: Record<string, number> = {};
    for (const f of findings) {
      const key = String(f.severity);
      out[key] = (out[key] ?? 0) + 1;
    }
    return out;
  }, [findings]);

  const visible = useMemo(() => {
    const filtered = severity
      ? findings.filter((f) => String(f.severity) === severity)
      : [...findings];
    return filtered.sort((a, b) => rank(a) - rank(b) || a.finding_id.localeCompare(b.finding_id));
  }, [findings, severity]);

  if (findings.length === 0) {
    return (
      <EmptyState
        title="No findings"
        description="No analysis stage recorded a finding for this sample. That is not the same as a clean verdict — check the pipeline stages for anything that was skipped or failed."
      />
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Findings ({findings.length})</CardTitle>
        <div className="mt-2 flex flex-wrap gap-2">
          <FilterChip active={severity === null} onClick={() => setSeverity(null)}>
            All {findings.length}
          </FilterChip>
          {SEVERITY_FILTERS.filter((s) => counts[s]).map((s) => (
            <FilterChip key={s} active={severity === s} onClick={() => setSeverity(s)}>
              {s} {counts[s]}
            </FilterChip>
          ))}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {visible.map((finding) => (
          <FindingRow key={`${finding.source_engine}:${finding.finding_id}`} finding={finding} />
        ))}
      </CardContent>
    </Card>
  );
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize transition-colors',
        active ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted',
      )}
    >
      {children}
    </button>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const provenance = finding.provenance ?? {};
  const hasProvenance = Object.keys(provenance).length > 0;

  return (
    <div className="rounded-md border">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-start gap-3 p-3 text-left transition-colors hover:bg-muted/40"
      >
        <ChevronRight
          className={cn(
            'mt-0.5 h-4 w-4 shrink-0 text-muted-foreground transition-transform',
            open && 'rotate-90',
          )}
          aria-hidden
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={String(finding.severity)} />
            <span className="font-medium capitalize">{finding.type.replace(/_/g, ' ')}</span>
          </div>
          {finding.detail && (
            <p className={cn('mt-1 text-sm text-muted-foreground', !open && 'line-clamp-2')}>
              {finding.detail}
            </p>
          )}
        </div>
        <span className="shrink-0 text-xs text-muted-foreground">{finding.source_engine}</span>
      </button>

      {open && (
        <div className="border-t px-3 py-3 text-sm">
          <dl className="grid gap-3 sm:grid-cols-2">
            <div>
              <dt className="text-xs text-muted-foreground">Finding ID</dt>
              <dd className="mt-0.5 font-mono text-xs">{finding.finding_id}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Confidence</dt>
              <dd className="mt-0.5 capitalize">
                {confidenceLabel(finding.confidence)}
                {finding.confidence != null && (
                  <span className="ml-1 text-xs tabular-nums text-muted-foreground">
                    ({finding.confidence.toFixed(2)})
                  </span>
                )}
              </dd>
            </div>
            {finding.mitre.length > 0 && (
              <div>
                <dt className="text-xs text-muted-foreground">MITRE ATT&amp;CK</dt>
                <dd className="mt-0.5 flex flex-wrap gap-1">
                  {finding.mitre.map((t) => (
                    <span key={t} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                      {t}
                    </span>
                  ))}
                </dd>
              </div>
            )}
            {finding.owasp_mobile.length > 0 && (
              <div>
                <dt className="text-xs text-muted-foreground">OWASP Mobile</dt>
                <dd className="mt-0.5 flex flex-wrap gap-1">
                  {finding.owasp_mobile.map((c) => (
                    <span key={c} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                      {c}
                    </span>
                  ))}
                </dd>
              </div>
            )}
          </dl>

          <div className="mt-3">
            <p className="text-xs font-medium text-muted-foreground">Evidence</p>
            {hasProvenance ? (
              <pre className="mt-1 max-h-64 overflow-auto rounded bg-muted p-2 text-xs">
                {JSON.stringify(provenance, null, 2)}
              </pre>
            ) : (
              // Said plainly: an unsourced finding is weaker than a sourced one,
              // and hiding that would overstate the platform's confidence.
              <p className="mt-1 text-xs text-muted-foreground">
                This finding carries no provenance. It cannot be traced to a specific artifact —
                treat it as a lead rather than as evidence.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
