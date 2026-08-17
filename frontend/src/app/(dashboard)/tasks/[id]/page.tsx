'use client';

import { useParams } from 'next/navigation';
import Link from 'next/link';
import { Card, CardContent } from '@/components/ui/card';
import { StatusBadge, TierBadge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/ui/page-header';
import { LoadingState, ErrorState } from '@/components/ui/feedback';
import { StageList } from '@/components/features/stage-list';
import { useJob, useJobStages, useCancelJob } from '@/lib/hooks/use-jobs';
import { formatDate } from '@/lib/utils';

// Task / job status page — polls live until the job reaches a terminal state.
export default function TaskDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: job, isLoading, isError, error, refetch } = useJob(id);
  const active = job?.status === 'running' || job?.status === 'queued';
  // Stage detail carries the version, attempt count, and skip/failure reason that
  // the inline stages on the job do not.
  const { data: stages } = useJobStages(id, Boolean(active));
  const cancel = useCancelJob();

  if (isLoading) return <LoadingState label="Loading job…" />;
  if (isError || !job) return <ErrorState error={error} retry={refetch} />;

  // A partial job is finished and has a report; it just did not run everything.
  const hasReport = job.status === 'completed' || job.status === 'partial';

  return (
    <div>
      <PageHeader
        title="Analysis status"
        description={job.job_id}
        action={
          <div className="flex gap-2">
            {active && (
              <Button
                variant="destructive"
                size="sm"
                loading={cancel.isPending}
                onClick={() => cancel.mutate(job.job_id)}
              >
                Cancel
              </Button>
            )}
            {hasReport && (
              <Link href={`/reports/${job.job_id}`}>
                <Button size="sm">View report</Button>
              </Link>
            )}
          </div>
        }
      />

      <Card className="mb-4">
        <CardContent className="flex flex-wrap items-center gap-6 py-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Status</span>
            <StatusBadge status={job.status} />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Risk</span>
            <TierBadge tier={job.risk_tier} />
            {job.risk_score != null && (
              <span className="text-sm font-medium tabular-nums">{job.risk_score.toFixed(1)}</span>
            )}
          </div>
          <div className="min-w-[200px] flex-1">
            <div className="mb-1 flex justify-between text-xs text-muted-foreground">
              <span>Progress</span>
              <span>{job.progress}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${job.progress}%` }}
              />
            </div>
          </div>
          <div className="text-sm text-muted-foreground">Created {formatDate(job.created_at)}</div>
        </CardContent>
      </Card>

      <StageList stages={stages} fallback={job.stages} />

      {job.error && <p className="mt-4 text-sm text-destructive">Error: {job.error}</p>}
    </div>
  );
}
