'use client';

import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PageHeader } from '@/components/ui/page-header';
import { LoadingState, ErrorState } from '@/components/ui/feedback';
import { Button } from '@/components/ui/button';
import { useJobs } from '@/lib/hooks/use-jobs';
import type { Job } from '@/lib/api/types';

function StatCard({ label, value }: { label: string; value: number | string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}

export default function DashboardPage() {
  const { data, isLoading, isError, error, refetch } = useJobs();

  const jobs: Job[] = data?.items ?? [];
  const running = jobs.filter((j) => j.status === 'running' || j.status === 'queued').length;
  const completed = jobs.filter((j) => j.status === 'completed').length;
  const failed = jobs.filter((j) => j.status === 'failed').length;

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Overview of APK analysis activity."
        action={
          <Link href="/upload">
            <Button>Upload APK</Button>
          </Link>
        }
      />

      {isLoading ? (
        <LoadingState />
      ) : isError ? (
        <ErrorState error={error} retry={refetch} />
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard label="Total analyses" value={jobs.length} />
          <StatCard label="In progress" value={running} />
          <StatCard label="Completed" value={completed} />
          <StatCard label="Failed" value={failed} />
        </div>
      )}
    </div>
  );
}
