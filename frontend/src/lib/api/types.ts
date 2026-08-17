// API contract types.
//
// These mirror backend contracts (docs/architecture/06-api-spec.md). In a later
// phase these are GENERATED from contracts/openapi — hand-written here for now
// so the whole dashboard is typed against a stable surface.

export interface Token {
  access_token: string;
  token_type: string;
  // /auth/login and /auth/refresh both return these. Dropping the refresh token
  // is what made sessions die the moment the access token expired.
  refresh_token: string;
  expires_in: number;
}

export type Role = 'admin' | 'analyst' | 'viewer';

export interface UserOut {
  id: string;
  email: string;
  role: Role;
  org_id: string | null;
}

export type JobStatus = 'queued' | 'running' | 'partial' | 'completed' | 'failed' | 'cancelled';

export type StageStatus = 'pending' | 'running' | 'ok' | 'partial' | 'failed' | 'skipped';

export interface StageInfo {
  engine: string;
  status: StageStatus;
  started_at?: string | null;
  finished_at?: string | null;
}

export type RiskTier = 'benign' | 'suspicious' | 'malicious' | 'critical';

export interface Job {
  job_id: string;
  sample_id: string;
  status: JobStatus;
  progress: number;
  pipeline_version?: string;
  stages: StageInfo[];
  error?: string | null;
  created_at: string;
  // Null until the scoring stage runs. Render "not scored" rather than 0 —
  // an unscored job is not a benign one.
  risk_score?: number | null;
  risk_tier?: RiskTier | string | null;
}

/** Per-stage detail from GET /jobs/{id}/stages. */
export interface StageDetail extends StageInfo {
  engine_version: string;
  attempt: number;
  // Why a stage was partial, failed, or skipped. A skipped stage without its
  // reason reads as a clean bill of health, which it is not.
  error?: string | null;
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  finding_id: string;
  source_engine: string;
  type: string;
  severity: Severity | string;
  confidence?: number | null;
  detail?: string | null;
  provenance?: Record<string, unknown> | null;
  mitre: string[];
  owasp_mobile: string[];
}

export interface FindingList {
  items: Finding[];
  total: number;
}

/** A raw Evidence Envelope. Analyst-gated and audited on the backend. */
export interface Evidence {
  evidence_id: string;
  engine: string;
  envelope_version: string;
  payload: Record<string, unknown>;
  large_artifact_uri?: string | null;
  created_at: string;
}

export interface EvidenceList {
  items: Evidence[];
}

export interface DomainScore {
  domain: string;
  weight: number;
  raw_score: number;
  weighted_score: number;
  finding_count: number;
  description: string;
}

/**
 * A synergy rule that fired. The least obvious part of the score: permissions
 * and behaviours that are unremarkable alone can be damning together.
 */
export interface SynergyBonus {
  rule_id: string;
  name: string;
  description: string;
  bonus: number;
  matched_domains: string[];
  matched_techniques: string[];
  confidence: number;
}

export interface ScoreBreakdown {
  final_score: number;
  base_score: number;
  synergy_bonus: number;
  tier: RiskTier | string;
  confidence: number;
  primary_category?: string | null;
  secondary_categories: string[];
  domain_scores: DomainScore[];
  synergy_bonuses: SynergyBonus[];
  key_findings: string[];
  scoring_version?: string | null;
}

export interface Report {
  job_id: string;
  report_id: string;
  generated_at?: string | null;
  // Absent for a job that produced no findings to score.
  score?: ScoreBreakdown | null;
  report: Record<string, unknown>;
  // format name → download path
  formats: Record<string, string>;
  warnings: string[];
}

export interface AuditEntry {
  id: string;
  created_at: string;
  action: string;
  outcome: string;
  actor_email?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  ip?: string | null;
  reason?: string | null;
}

export interface AuditList {
  items: AuditEntry[];
  total: number;
}

export interface Paginated<T> {
  items: T[];
  next_cursor: string | null;
}

// RFC 9457 Problem Details — the error envelope from the backend.
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  trace_id?: string | null;
  errors?: unknown;
}
