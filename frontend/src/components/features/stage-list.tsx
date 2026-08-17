'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { StatusBadge } from '@/components/ui/badge';
import type { StageDetail, StageInfo } from '@/lib/api/types';
import { formatDate } from '@/lib/utils';

// The pipeline's dependency order (app/tasks/pipeline.py). Stages are displayed
// in this order rather than by creation time so a stage that has not started yet
// still appears in the position it will run in.
const STAGE_ORDER = [
  'static',
  'code_intel',
  'dynamic',
  'threat_intel',
  'ai_orchestrator',
  'scoring',
  'reporting',
] as const;

const STAGE_LABELS: Record<string, string> = {
  static: 'Static analysis',
  code_intel: 'Code intelligence',
  dynamic: 'Dynamic analysis',
  threat_intel: 'Threat intelligence',
  ai_orchestrator: 'Multi-agent reasoning',
  scoring: 'Risk scoring',
  reporting: 'Report generation',
};

function label(engine: string): string {
  return STAGE_LABELS[engine] ?? engine.replace(/_/g, ' ');
}

function order(engine: string): number {
  const index = STAGE_ORDER.indexOf(engine as (typeof STAGE_ORDER)[number]);
  return index === -1 ? STAGE_ORDER.length : index;
}

function duration(stage: StageInfo): string | null {
  if (!stage.started_at || !stage.finished_at) return null;
  const ms = new Date(stage.finished_at).getTime() - new Date(stage.started_at).getTime();
  if (ms < 0) return null;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

/**
 * Per-stage progress with the reason each stage produced what it did.
 *
 * The reason is the reason this component exists. A skipped stage rendered as a
 * grey badge and nothing else reads as "fine" — but "dynamic analysis is
 * disabled" and "the sandbox crashed" mean very different things for how much the
 * verdict can be trusted, and only the recorded message distinguishes them.
 */
export function StageList({ stages, fallback }: { stages?: StageDetail[]; fallback: StageInfo[] }) {
  // Fall back to the inline stages on the job while the detail query is in
  // flight, so the list never blinks empty on a poll.
  const rows: (StageDetail | StageInfo)[] = stages?.length ? stages : fallback;
  const sorted = [...rows].sort((a, b) => order(a.engine) - order(b.engine));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Pipeline stages</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {sorted.length === 0 && (
          <p className="text-sm text-muted-foreground">Waiting for the pipeline to start…</p>
        )}
        {sorted.map((stage) => {
          const detail = stage as StageDetail;
          const elapsed = duration(stage);
          return (
            <div key={stage.engine} className="rounded-md border px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-medium">{label(stage.engine)}</span>
                <div className="flex items-center gap-3">
                  {elapsed && (
                    <span className="text-xs tabular-nums text-muted-foreground">{elapsed}</span>
                  )}
                  {detail.attempt > 1 && (
                    <span className="text-xs text-muted-foreground">attempt {detail.attempt}</span>
                  )}
                  <StatusBadge status={stage.status} />
                </div>
              </div>

              {detail.error && (
                <p
                  className={
                    stage.status === 'failed'
                      ? 'mt-1 text-xs text-destructive'
                      : 'mt-1 text-xs text-muted-foreground'
                  }
                >
                  {detail.error}
                </p>
              )}

              {detail.engine_version && (
                <p className="mt-1 text-xs text-muted-foreground">
                  <span className="font-mono">
                    {stage.engine} v{detail.engine_version}
                  </span>
                  {stage.started_at && <> · started {formatDate(stage.started_at)}</>}
                </p>
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
