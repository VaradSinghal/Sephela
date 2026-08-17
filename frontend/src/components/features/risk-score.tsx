'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { TierBadge } from '@/components/ui/badge';
import type { ScoreBreakdown } from '@/lib/api/types';
import { cn } from '@/lib/utils';

// Tier → the severity token used for the gauge arc and the domain bars. Matches
// TierBadge so the number and the label never disagree visually.
const TIER_STROKE: Record<string, string> = {
  benign: 'stroke-severity-low',
  suspicious: 'stroke-severity-medium',
  malicious: 'stroke-severity-high',
  critical: 'stroke-severity-critical',
};

const TIER_FILL: Record<string, string> = {
  benign: 'bg-severity-low',
  suspicious: 'bg-severity-medium',
  malicious: 'bg-severity-high',
  critical: 'bg-severity-critical',
};

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

/**
 * The headline score as a ring gauge.
 *
 * The gauge shows base vs. synergy as two arcs rather than one total, because
 * those are different claims: the base score is the sum of what each domain
 * independently justified, and the synergy bonus is what only the combination
 * does. Collapsing them would hide the part an analyst is most likely to be
 * challenged on.
 */
export function RiskScoreGauge({ score }: { score: ScoreBreakdown }) {
  const tier = String(score.tier);
  const total = Math.max(0, Math.min(100, score.final_score));
  const basePortion = Math.max(0, Math.min(total, score.base_score));

  const baseDash = (basePortion / 100) * CIRCUMFERENCE;
  const totalDash = (total / 100) * CIRCUMFERENCE;

  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-8 py-6">
        <div className="relative h-32 w-32 shrink-0">
          <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
            <circle
              cx="60"
              cy="60"
              r={RADIUS}
              fill="none"
              strokeWidth="10"
              className="stroke-muted"
            />
            {/* Synergy sits outside the base arc, drawn first so the base
                overlays it — the visible tail is the bonus. */}
            {score.synergy_bonus > 0 && (
              <circle
                cx="60"
                cy="60"
                r={RADIUS}
                fill="none"
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={`${totalDash} ${CIRCUMFERENCE}`}
                className={cn('opacity-40', TIER_STROKE[tier] ?? 'stroke-muted-foreground')}
              />
            )}
            <circle
              cx="60"
              cy="60"
              r={RADIUS}
              fill="none"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={`${baseDash} ${CIRCUMFERENCE}`}
              className={TIER_STROKE[tier] ?? 'stroke-muted-foreground'}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-semibold tabular-nums">{total.toFixed(1)}</span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
        </div>

        <dl className="grid flex-1 grid-cols-2 gap-x-8 gap-y-3 text-sm sm:grid-cols-3">
          <div>
            <dt className="text-xs text-muted-foreground">Tier</dt>
            <dd className="mt-1">
              <TierBadge tier={tier} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Category</dt>
            <dd className="mt-1 font-medium capitalize">
              {score.primary_category?.replace(/_/g, ' ') ?? '—'}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Confidence</dt>
            <dd className="mt-1 font-medium tabular-nums">
              {Math.round((score.confidence ?? 0) * 100)}%
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Base score</dt>
            <dd className="mt-1 font-medium tabular-nums">{score.base_score.toFixed(1)}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Synergy bonus</dt>
            <dd className="mt-1 font-medium tabular-nums">
              {score.synergy_bonus > 0 ? `+${score.synergy_bonus.toFixed(1)}` : '—'}
            </dd>
          </div>
          {score.scoring_version && (
            <div>
              <dt className="text-xs text-muted-foreground">Scoring version</dt>
              <dd className="mt-1 font-mono text-xs">{score.scoring_version}</dd>
            </div>
          )}
        </dl>
      </CardContent>
    </Card>
  );
}

/** Per-domain contributions, ordered by what actually moved the score. */
export function ScoreDecomposition({ score }: { score: ScoreBreakdown }) {
  const tier = String(score.tier);
  const domains = [...score.domain_scores].sort((a, b) => b.weighted_score - a.weighted_score);
  const max = Math.max(...domains.map((d) => d.weighted_score), 1);

  if (domains.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Score decomposition</CardTitle>
        <p className="text-sm text-muted-foreground">
          Each domain contributes its worst finding, weighted by the domain&apos;s share of the
          model. Contributions sum to the base score.
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {domains.map((domain) => (
          <div key={domain.domain}>
            <div className="mb-1 flex items-baseline justify-between gap-4 text-sm">
              <span className="font-medium capitalize">{domain.domain.replace(/_/g, ' ')}</span>
              <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
                {domain.weighted_score.toFixed(1)} pts · raw {domain.raw_score.toFixed(0)} × weight{' '}
                {domain.weight.toFixed(2)} · {domain.finding_count}{' '}
                {domain.finding_count === 1 ? 'finding' : 'findings'}
              </span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className={cn('h-full transition-all', TIER_FILL[tier] ?? 'bg-primary')}
                style={{ width: `${(domain.weighted_score / max) * 100}%` }}
              />
            </div>
            {domain.description && (
              <p className="mt-1 text-xs text-muted-foreground">{domain.description}</p>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

/**
 * The synergy rules that fired.
 *
 * Surfaced as its own section because it is the least intuitive part of the
 * score: each of these permissions or behaviours can be unremarkable alone, and
 * the bonus exists precisely because the combination is not.
 */
export function SynergyRules({ score }: { score: ScoreBreakdown }) {
  if (score.synergy_bonuses.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Synergy rules triggered</CardTitle>
        <p className="text-sm text-muted-foreground">
          Combinations that are more dangerous together than the sum of their parts. These added{' '}
          {score.synergy_bonus.toFixed(1)} points beyond the per-domain base.
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {score.synergy_bonuses.map((rule) => (
          <div key={rule.rule_id} className="rounded-md border p-3">
            <div className="flex items-baseline justify-between gap-4">
              <span className="text-sm font-medium">{rule.name}</span>
              <span className="shrink-0 text-xs font-medium tabular-nums text-severity-high">
                +{rule.bonus.toFixed(1)}
              </span>
            </div>
            <p className="mt-1 text-sm text-muted-foreground">{rule.description}</p>
            {(rule.matched_domains.length > 0 || rule.matched_techniques.length > 0) && (
              <div className="mt-2 flex flex-wrap gap-1">
                {rule.matched_domains.map((d) => (
                  <span
                    key={d}
                    className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
                  >
                    {d}
                  </span>
                ))}
                {rule.matched_techniques.map((t) => (
                  <span key={t} className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
