'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';
import { AlertTriangle, Download } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { StatusBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/ui/page-header';
import { LoadingState, ErrorState, EmptyState } from '@/components/ui/feedback';
import { RiskScoreGauge, ScoreDecomposition, SynergyRules } from '@/components/features/risk-score';
import { FindingsList } from '@/components/features/findings-list';
import { ApiError } from '@/lib/api/client';
import { useJob, useJobFindings } from '@/lib/hooks/use-jobs';
import { useReport, useDownloadReport } from '@/lib/hooks/use-report';
import { formatDate } from '@/lib/utils';

// Preferred download order — most useful to a human first.
const FORMAT_LABELS: Record<string, string> = {
  pdf: 'PDF',
  html: 'HTML',
  markdown: 'Markdown',
  json: 'JSON',
  sarif: 'SARIF',
};
const FORMAT_ORDER = ['pdf', 'html', 'markdown', 'json', 'sarif'];

export default function ReportDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: job, isLoading: jobLoading, isError: jobFailed, error: jobError } = useJob(id);
  const report = useReport(id);
  const findings = useJobFindings(id, { limit: 500 });
  const download = useDownloadReport(id);

  if (jobLoading) return <LoadingState label="Loading report…" />;
  if (jobFailed || !job) return <ErrorState error={jobError} />;

  const active = job.status === 'queued' || job.status === 'running';
  const notGenerated = report.error instanceof ApiError && report.error.status === 404;

  if (active) {
    return (
      <div>
        <PageHeader title="Report" description={job.job_id} />
        <EmptyState
          title="Analysis still running"
          description={
            <>
              This job is <StatusBadge status={job.status} />. Track progress on the{' '}
              <Link href={`/tasks/${job.job_id}`} className="text-primary underline">
                status page
              </Link>
              .
            </>
          }
        />
      </div>
    );
  }

  if (notGenerated) {
    return (
      <div>
        <PageHeader title="Report" description={job.job_id} />
        <EmptyState
          title="No report was generated"
          description={
            <>
              The reporting stage produced nothing for this job — it may have been disabled, or no
              stage produced evidence to report on. The{' '}
              <Link href={`/tasks/${job.job_id}`} className="text-primary underline">
                stage list
              </Link>{' '}
              records the reason.
            </>
          }
        />
      </div>
    );
  }

  if (report.isLoading) return <LoadingState label="Loading report…" />;
  if (report.isError) return <ErrorState error={report.error} retry={report.refetch} />;

  const data = report.data;
  const formats = FORMAT_ORDER.filter((f) => data?.formats[f]);
  const summary = (data?.report as { executive_summary?: Record<string, unknown> } | undefined)
    ?.executive_summary;
  const overview = typeof summary?.overview === 'string' ? summary.overview : null;
  const actions = Array.isArray(summary?.recommended_actions)
    ? (summary.recommended_actions as string[])
    : [];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Report"
        description={job.job_id}
        action={
          <div className="flex flex-wrap gap-2">
            {formats.map((format) => (
              <Button
                key={format}
                variant="secondary"
                size="sm"
                loading={download.isPending && download.variables === format}
                onClick={() => download.mutate(format)}
              >
                <Download className="h-4 w-4" aria-hidden />
                {FORMAT_LABELS[format] ?? format.toUpperCase()}
              </Button>
            ))}
          </div>
        }
      />

      {download.isError && (
        <p className="text-sm text-destructive">
          Download failed: {(download.error as Error).message}
        </p>
      )}

      {/* A partial job produced a report over incomplete analysis. Saying so up
          front matters more than the score itself. */}
      {job.status === 'partial' && (
        <div className="flex items-start gap-2 rounded-md border border-severity-medium/40 bg-severity-medium/10 p-3 text-sm">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-severity-medium" aria-hidden />
          <p>
            Analysis was incomplete — some stages were skipped or failed, so this report covers less
            than a full run. See the{' '}
            <Link href={`/tasks/${job.job_id}`} className="text-primary underline">
              stage list
            </Link>{' '}
            for what is missing.
          </p>
        </div>
      )}

      {data?.warnings.length ? (
        <div className="rounded-md border border-severity-medium/40 bg-severity-medium/10 p-3 text-sm">
          <p className="font-medium">Report generated with warnings</p>
          <ul className="mt-1 list-inside list-disc text-muted-foreground">
            {data.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {data?.score ? (
        <>
          <RiskScoreGauge score={data.score} />
          <ScoreDecomposition score={data.score} />
          <SynergyRules score={data.score} />
        </>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Not scored</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              No risk score was computed for this job, so this report carries findings without a
              tier. An unscored sample is not a benign one.
            </p>
          </CardContent>
        </Card>
      )}

      {overview && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Summary</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <p className="text-sm">{overview}</p>
            {actions.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">Recommended actions</p>
                <ul className="mt-1 list-inside list-disc text-sm text-muted-foreground">
                  {actions.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {findings.isLoading ? (
        <LoadingState label="Loading findings…" />
      ) : findings.isError ? (
        <ErrorState error={findings.error} retry={findings.refetch} />
      ) : (
        <FindingsList findings={findings.data?.items ?? []} />
      )}

      <p className="text-xs text-muted-foreground">
        Report {data?.report_id} · generated {formatDate(data?.generated_at)}
      </p>
    </div>
  );
}
