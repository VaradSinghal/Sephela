// The headline number and its decomposition. The gauge draws base and synergy as two
// arcs on purpose: the base is what each domain independently justified and the bonus is
// what only the combination does, and collapsing them would hide the part of the score
// an analyst is most likely to be challenged on.

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RiskScoreGauge, ScoreDecomposition, SynergyRules } from './risk-score';
import type { DomainScore, ScoreBreakdown, SynergyBonus } from '@/lib/api/types';

function domain(overrides: Partial<DomainScore> = {}): DomainScore {
  return {
    domain: 'permissions',
    raw_score: 90,
    weight: 0.3,
    weighted_score: 27,
    finding_count: 3,
    ...overrides,
  } as DomainScore;
}

function synergy(overrides: Partial<SynergyBonus> = {}): SynergyBonus {
  return {
    rule_id: 'overlay-accessibility',
    name: 'Overlay + accessibility',
    description: 'Screen reading combined with window overlay is the banking-trojan shape.',
    bonus: 12,
    matched_domains: ['permissions'],
    matched_techniques: ['T1417.001'],
    ...overrides,
  } as SynergyBonus;
}

function breakdown(overrides: Partial<ScoreBreakdown> = {}): ScoreBreakdown {
  return {
    final_score: 72,
    base_score: 60,
    synergy_bonus: 12,
    tier: 'malicious',
    confidence: 0.85,
    primary_category: 'banking_trojan',
    scoring_version: '2026.1',
    domain_scores: [domain()],
    synergy_bonuses: [synergy()],
    ...overrides,
  } as ScoreBreakdown;
}

describe('RiskScoreGauge', () => {
  it('shows the final score to one decimal place', () => {
    render(<RiskScoreGauge score={breakdown({ final_score: 72.36 })} />);

    expect(screen.getByText('72.4')).toBeInTheDocument();
  });

  it('shows a whole score with its decimal', () => {
    // "72" and "72.0" read differently next to a decomposition whose parts have them.
    render(<RiskScoreGauge score={breakdown({ final_score: 72 })} />);

    expect(screen.getByText('72.0')).toBeInTheDocument();
  });

  it('shows the tier and the category', () => {
    render(<RiskScoreGauge score={breakdown()} />);

    expect(screen.getByText('malicious')).toBeInTheDocument();
    expect(screen.getByText('banking trojan')).toBeInTheDocument();
  });

  it('shows confidence as a whole percentage', () => {
    render(<RiskScoreGauge score={breakdown({ confidence: 0.856 })} />);

    expect(screen.getByText('86%')).toBeInTheDocument();
  });

  it('shows base and synergy separately', () => {
    // The two claims are different, and an analyst defending the score needs both.
    render(<RiskScoreGauge score={breakdown({ base_score: 60, synergy_bonus: 12 })} />);

    expect(screen.getByText('60.0')).toBeInTheDocument();
    expect(screen.getByText('+12.0')).toBeInTheDocument();
  });

  it('renders an em dash rather than +0.0 when no synergy fired', () => {
    render(<RiskScoreGauge score={breakdown({ synergy_bonus: 0 })} />);

    expect(screen.queryByText('+0.0')).not.toBeInTheDocument();
  });

  it('clamps a score above 100', () => {
    // The arc is a fraction of a circumference; an over-100 score would wrap it round
    // and read as a low score.
    render(<RiskScoreGauge score={breakdown({ final_score: 140 })} />);

    expect(screen.getByText('100.0')).toBeInTheDocument();
  });

  it('clamps a negative score', () => {
    render(<RiskScoreGauge score={breakdown({ final_score: -5 })} />);

    expect(screen.getByText('0.0')).toBeInTheDocument();
  });

  it('renders a zero confidence as 0%, not as absent', () => {
    // `confidence` is non-nullable in both the API schema and the TS type, so the
    // interesting case is the low end rather than a missing value.
    render(<RiskScoreGauge score={breakdown({ confidence: 0 })} />);

    expect(screen.getByText('0%')).toBeInTheDocument();
  });

  it('handles a missing category', () => {
    render(<RiskScoreGauge score={breakdown({ primary_category: null })} />);

    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('colours the arc from the tier', () => {
    const { container } = render(<RiskScoreGauge score={breakdown({ tier: 'critical' })} />);

    expect(container.innerHTML).toContain('stroke-severity-critical');
  });

  it('omits the synergy arc entirely when there is no bonus', () => {
    const { container } = render(<RiskScoreGauge score={breakdown({ synergy_bonus: 0 })} />);

    // One background circle plus one base arc, and no third overlay.
    expect(container.querySelectorAll('circle')).toHaveLength(2);
  });

  it('draws the synergy arc when there is a bonus', () => {
    const { container } = render(<RiskScoreGauge score={breakdown({ synergy_bonus: 12 })} />);

    expect(container.querySelectorAll('circle')).toHaveLength(3);
  });

  it('shows the scoring version so a stored score stays interpretable', () => {
    // The model changes; a score without its version cannot be compared to a later one.
    render(<RiskScoreGauge score={breakdown({ scoring_version: '2026.1' })} />);

    expect(screen.getByText('2026.1')).toBeInTheDocument();
  });
});

describe('ScoreDecomposition', () => {
  it('orders domains by what actually moved the score', () => {
    const { container } = render(
      <ScoreDecomposition
        score={breakdown({
          domain_scores: [
            domain({ domain: 'network', weighted_score: 5 }),
            domain({ domain: 'permissions', weighted_score: 27 }),
            domain({ domain: 'code', weighted_score: 14 }),
          ],
        })}
      />,
    );

    const labels = [...container.querySelectorAll('.capitalize')].map((n) => n.textContent);
    expect(labels).toEqual(['permissions', 'code', 'network']);
  });

  it('shows the raw score, the weight, and the finding count behind each bar', () => {
    // The bar alone is not auditable; these three numbers are what reproduce it.
    render(
      <ScoreDecomposition
        score={breakdown({
          domain_scores: [
            domain({ raw_score: 90, weight: 0.3, weighted_score: 27, finding_count: 3 }),
          ],
        })}
      />,
    );

    expect(screen.getByText(/27\.0 pts/)).toBeInTheDocument();
    expect(screen.getByText(/raw 90/)).toBeInTheDocument();
    expect(screen.getByText(/weight 0\.30/)).toBeInTheDocument();
    expect(screen.getByText(/3 findings/)).toBeInTheDocument();
  });

  it('says "finding" for exactly one', () => {
    render(
      <ScoreDecomposition score={breakdown({ domain_scores: [domain({ finding_count: 1 })] })} />,
    );

    expect(screen.getByText(/1 finding(?!s)/)).toBeInTheDocument();
  });

  it('renders nothing when no domain scored', () => {
    const { container } = render(<ScoreDecomposition score={breakdown({ domain_scores: [] })} />);

    expect(container).toBeEmptyDOMElement();
  });

  it('does not divide by zero when every domain scored zero', () => {
    render(
      <ScoreDecomposition
        score={breakdown({ domain_scores: [domain({ weighted_score: 0, finding_count: 0 })] })}
      />,
    );

    expect(screen.getByText(/0\.0 pts/)).toBeInTheDocument();
  });
});

describe('SynergyRules', () => {
  it('names each rule that fired and what it added', () => {
    render(<SynergyRules score={breakdown()} />);

    expect(screen.getByText('Overlay + accessibility')).toBeInTheDocument();
    expect(screen.getByText('+12.0')).toBeInTheDocument();
  });

  it('explains why the combination matters', () => {
    // Each permission can be unremarkable alone, which is exactly why the bonus needs
    // its own explanation rather than just a number.
    render(<SynergyRules score={breakdown()} />);

    expect(screen.getByText(/banking-trojan shape/)).toBeInTheDocument();
  });

  it('lists the domains and techniques it matched on', () => {
    render(<SynergyRules score={breakdown()} />);

    expect(screen.getByText('permissions')).toBeInTheDocument();
    expect(screen.getByText('T1417.001')).toBeInTheDocument();
  });

  it('renders nothing when no rule fired', () => {
    const { container } = render(<SynergyRules score={breakdown({ synergy_bonuses: [] })} />);

    expect(container).toBeEmptyDOMElement();
  });

  it('renders a rule that matched nothing specific', () => {
    render(
      <SynergyRules
        score={breakdown({
          synergy_bonuses: [synergy({ matched_domains: [], matched_techniques: [] })],
        })}
      />,
    );

    expect(screen.getByText('Overlay + accessibility')).toBeInTheDocument();
  });

  it('reports the total the rules contributed', () => {
    render(<SynergyRules score={breakdown({ synergy_bonus: 12 })} />);

    expect(screen.getByText(/added 12\.0 points/)).toBeInTheDocument();
  });
});
