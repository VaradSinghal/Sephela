'use client';

import Link from 'next/link';
import { Card, CardContent } from '@/components/ui/card';
import { StatusBadge, TierBadge } from '@/components/ui/badge';
import { LoadingState, ErrorState, EmptyState } from '@/components/ui/feedback';
import { useJobs } from '@/lib/hooks/use-jobs';
import { formatDate } from '@/lib/utils';

// Reusable list of analysis jobs, linking to their status page. Shared by the
// Tasks and Reports views (Reports filters to completed).
export function JobList({
  status,
  hrefBase = '/tasks',
  emptyTitle = 'No analyses yet',
  emptyDescription = 'Upload an APK to get started.',
}: {
  status?: string | string[];
  hrefBase?: string;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  const { data, isLoading, isError, error, refetch } = useJobs(status);

  if (isLoading) return <LoadingState />;
  if (isError) return <ErrorState error={error} retry={refetch} />;

  const jobs = data?.items ?? [];
  if (jobs.length === 0) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />;
  }

  return (
    <div className="flex flex-col gap-2">
      {jobs.map((job) => (
        <Link key={job.job_id} href={`${hrefBase}/${job.job_id}`}>
          <Card className="transition-colors hover:bg-muted/40">
            <CardContent className="flex items-center justify-between gap-4 py-4">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm">{job.job_id}</p>
                <p className="text-xs text-muted-foreground">{formatDate(job.created_at)}</p>
              </div>
              <div className="flex items-center gap-3">
                {job.risk_score != null && (
                  <span className="text-sm font-medium tabular-nums">
                    {job.risk_score.toFixed(1)}
                  </span>
                )}
                <TierBadge tier={job.risk_tier} />
                <span className="text-sm text-muted-foreground">{job.progress}%</span>
                <StatusBadge status={job.status} />
              </div>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  );
}
