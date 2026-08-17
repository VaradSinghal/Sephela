import type { HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';
import type { JobStatus, StageStatus } from '@/lib/api/types';

// Risk tier → the severity token that reads as the same level of alarm. Kept
// separate from statusStyles: a tier is a judgement about the sample, a status is
// a fact about the pipeline, and colouring them from one table would let a
// "completed" job look reassuring next to a "critical" verdict.
const tierStyles: Record<string, string> = {
  benign: 'bg-severity-low/15 text-severity-low',
  suspicious: 'bg-severity-medium/15 text-severity-medium',
  malicious: 'bg-severity-high/15 text-severity-high',
  critical: 'bg-severity-critical/15 text-severity-critical',
};

const severityStyles: Record<string, string> = {
  info: 'bg-severity-info/15 text-severity-info',
  low: 'bg-severity-low/15 text-severity-low',
  medium: 'bg-severity-medium/15 text-severity-medium',
  high: 'bg-severity-high/15 text-severity-high',
  critical: 'bg-severity-critical/15 text-severity-critical',
};

const base = 'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize';

const statusStyles: Record<string, string> = {
  queued: 'bg-muted text-muted-foreground',
  pending: 'bg-muted text-muted-foreground',
  running: 'bg-severity-info/15 text-severity-info',
  ok: 'bg-severity-low/15 text-severity-low',
  completed: 'bg-severity-low/15 text-severity-low',
  partial: 'bg-severity-medium/15 text-severity-medium',
  skipped: 'bg-muted text-muted-foreground',
  failed: 'bg-severity-critical/15 text-severity-critical',
  cancelled: 'bg-muted text-muted-foreground',
};

interface StatusBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  status: JobStatus | StageStatus | string;
}

export function StatusBadge({ status, className, ...props }: StatusBadgeProps) {
  return (
    <span
      className={cn(base, statusStyles[status] ?? 'bg-muted text-muted-foreground', className)}
      {...props}
    >
      {status}
    </span>
  );
}

/**
 * A risk tier, or "not scored" when scoring did not run.
 *
 * An unscored job must never render as benign — that is a false reassurance, not
 * a cosmetic difference.
 */
export function TierBadge({
  tier,
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tier?: string | null }) {
  if (!tier) {
    return (
      <span className={cn(base, 'bg-muted text-muted-foreground', className)} {...props}>
        not scored
      </span>
    );
  }
  return (
    <span
      className={cn(base, tierStyles[tier] ?? 'bg-muted text-muted-foreground', className)}
      {...props}
    >
      {tier}
    </span>
  );
}

export function SeverityBadge({
  severity,
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & { severity: string }) {
  return (
    <span
      className={cn(base, severityStyles[severity] ?? 'bg-muted text-muted-foreground', className)}
      {...props}
    >
      {severity}
    </span>
  );
}
