'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { jobsApi, uploadsApi } from '@/lib/api/endpoints';
import type { Job } from '@/lib/api/types';

// "partial" is terminal too: the job finished, some stages just did not.
const TERMINAL: Job['status'][] = ['completed', 'partial', 'failed', 'cancelled'];

const POLL_MS = 3000;

export function useJobs(status?: string | string[]) {
  const key = Array.isArray(status) ? status.join(',') : (status ?? 'all');
  return useQuery({
    queryKey: ['jobs', key],
    queryFn: () => jobsApi.list({ status }),
  });
}

export function useJob(id: string) {
  return useQuery({
    queryKey: ['job', id],
    queryFn: () => jobsApi.get(id),
    // Poll while the job is still running (docs/architecture/06-api-spec.md).
    refetchInterval: (query) => {
      const data = query.state.data as Job | undefined;
      return data && TERMINAL.includes(data.status) ? false : POLL_MS;
    },
  });
}

/**
 * Per-stage detail, polled alongside the job.
 *
 * Separate from `useJob` because the inline `stages` on a Job carries status
 * only — the engine version, attempt count, and the reason a stage was
 * skipped or failed live here, and that reason is what an analyst needs to know
 * a stage produced nothing on purpose.
 */
export function useJobStages(id: string, isActive: boolean) {
  return useQuery({
    queryKey: ['job', id, 'stages'],
    queryFn: () => jobsApi.stages(id),
    refetchInterval: isActive ? POLL_MS : false,
  });
}

export function useJobFindings(
  id: string,
  params?: { severity?: string; type?: string; limit?: number },
) {
  return useQuery({
    queryKey: ['job', id, 'findings', params ?? {}],
    queryFn: () => jobsApi.findings(id, params),
  });
}

/** Raw Evidence Envelopes. Analyst-gated server-side, and the access is audited. */
export function useJobEvidence(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ['job', id, 'evidence'],
    queryFn: () => jobsApi.evidence(id),
    enabled,
  });
}

export function useUpload() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => uploadsApi.upload(file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
  });
}

export function useCancelJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => jobsApi.cancel(id),
    onSuccess: (_d, id) => {
      qc.invalidateQueries({ queryKey: ['job', id] });
      qc.invalidateQueries({ queryKey: ['jobs'] });
    },
  });
}
