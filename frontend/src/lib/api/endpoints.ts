// Endpoint functions grouped by domain. Components use the hooks in
// lib/hooks; these are the thin typed wrappers over the API client.

import { api } from './client';
import type {
  AuditList,
  EvidenceList,
  FindingList,
  Job,
  Paginated,
  Report,
  StageDetail,
  Token,
  UserOut,
} from './types';

export const authApi = {
  login: (email: string, password: string) =>
    api.post<Token>('/auth/login', { email, password }, { auth: false }),
  // No bearer header: the refresh token in the body is the credential, and the
  // access token this call replaces may already be expired.
  refresh: (refreshToken: string) =>
    api.post<Token>('/auth/refresh', { refresh_token: refreshToken }, { auth: false }),
  me: () => api.get<UserOut>('/auth/me'),
  // Admin-only, and scoped to the caller's own organisation server-side.
  audit: (params?: { action?: string; limit?: number }) =>
    api.get<AuditList>(`/auth/audit${qs({ action: params?.action, limit: params?.limit })}`),
};

export const jobsApi = {
  // `status` is repeatable server-side: "has a report" is completed OR partial.
  list: (params?: { status?: string | string[]; limit?: number }) => {
    const q = new URLSearchParams();
    const statuses = params?.status;
    for (const s of Array.isArray(statuses) ? statuses : statuses ? [statuses] : []) {
      q.append('status', s);
    }
    if (params?.limit) q.set('limit', String(params.limit));
    const s = q.toString();
    return api.get<Paginated<Job>>(`/jobs${s ? `?${s}` : ''}`);
  },
  get: (id: string) => api.get<Job>(`/jobs/${id}`),
  // Per-stage detail: engine version, attempt count, and the reason a stage was
  // partial/failed/skipped. The inline `stages` on a Job carries only status.
  stages: (id: string) => api.get<StageDetail[]>(`/jobs/${id}/stages`),
  findings: (id: string, params?: { type?: string; severity?: string; limit?: number }) =>
    api.get<FindingList>(`/jobs/${id}/findings${qs(params)}`),
  // Analyst-gated and audited server-side — raw sample-derived content.
  evidence: (id: string, engine?: string) =>
    api.get<EvidenceList>(`/jobs/${id}/evidence${qs({ engine })}`),
  cancel: (id: string) => api.post<Job>(`/jobs/${id}/cancel`),
};

export const reportsApi = {
  get: (id: string) => api.get<Report>(`/jobs/${id}/report`),
  // Fetched rather than linked: the download route needs the bearer token, which
  // a plain navigation cannot carry. useDownloadReport turns the blob into a save.
  artifact: (id: string, format: string) => api.blob(`/jobs/${id}/report/${format}`),
};

export const uploadsApi = {
  upload: (file: File) => {
    const fd = new FormData();
    fd.append('file', file);
    return api.post<{
      job_id: string;
      sample_id: string;
      sha256: string;
      status: string;
      duplicate: boolean;
    }>('/uploads', fd);
  },
};

/** Build a query string from defined values only, or "" when there are none. */
function qs(params?: Record<string, string | number | undefined | null>): string {
  if (!params) return '';
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') q.set(key, String(value));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}
