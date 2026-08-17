'use client';

import { useMutation, useQuery } from '@tanstack/react-query';
import { ApiError } from '@/lib/api/client';
import { reportsApi } from '@/lib/api/endpoints';

export function useReport(id: string) {
  return useQuery({
    queryKey: ['report', id],
    queryFn: () => reportsApi.get(id),
    // A 404 means the reporting stage has not produced anything for this job.
    // That is an answer, not a transient failure, so do not retry into it.
    retry: (count, error) => !(error instanceof ApiError && error.status === 404) && count < 2,
  });
}

/**
 * Download one rendered artifact.
 *
 * Fetched rather than linked: the download route needs the bearer token, which a
 * plain navigation cannot carry. The bytes come back as a blob and are handed to
 * the browser through a transient object URL.
 */
export function useDownloadReport(id: string) {
  return useMutation({
    mutationFn: async (format: string) => {
      const { blob, filename } = await reportsApi.artifact(id, format);
      const url = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename ?? `sephela-report-${id}.${format}`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        // Revoked on the next tick: Safari cancels an in-flight download if the
        // object URL is released synchronously after the click.
        setTimeout(() => URL.revokeObjectURL(url), 0);
      }
      return format;
    },
  });
}
