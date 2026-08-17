import { PageHeader } from '@/components/ui/page-header';
import { JobList } from '@/components/features/job-list';

export default function TasksPage() {
  return (
    <div>
      <PageHeader title="Tasks" description="All analysis jobs and their live status." />
      <JobList hrefBase="/tasks" />
    </div>
  );
}
