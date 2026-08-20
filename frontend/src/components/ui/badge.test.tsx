// Three badge families that deliberately do not share a colour table. The one
// behaviour that is a safety property rather than styling: an unscored job must never
// render as benign, because that is false reassurance rather than a cosmetic default.

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { SeverityBadge, StatusBadge, TierBadge } from './badge';

describe('TierBadge', () => {
  it('renders the tier it is given', () => {
    render(<TierBadge tier="malicious" />);

    expect(screen.getByText('malicious')).toBeInTheDocument();
  });

  it('says "not scored" rather than defaulting to benign', () => {
    // The scoring stage can be skipped or fail. Showing "benign" for a sample nobody
    // scored is the single most dangerous thing this component could do.
    render(<TierBadge tier={null} />);

    expect(screen.getByText('not scored')).toBeInTheDocument();
    expect(screen.queryByText('benign')).not.toBeInTheDocument();
  });

  it('says "not scored" for an absent tier too', () => {
    render(<TierBadge />);

    expect(screen.getByText('not scored')).toBeInTheDocument();
  });

  it('says "not scored" for an empty string', () => {
    render(<TierBadge tier="" />);

    expect(screen.getByText('not scored')).toBeInTheDocument();
  });

  it('renders an unrecognised tier as itself rather than swallowing it', () => {
    // A new tier added server-side should show up as unknown-but-present, not vanish.
    render(<TierBadge tier="catastrophic" />);

    expect(screen.getByText('catastrophic')).toBeInTheDocument();
  });

  it('escalates its colour with the tier', () => {
    const { container: benign } = render(<TierBadge tier="benign" />);
    const { container: critical } = render(<TierBadge tier="critical" />);

    expect(benign.firstElementChild?.className).toContain('severity-low');
    expect(critical.firstElementChild?.className).toContain('severity-critical');
  });
});

describe('StatusBadge', () => {
  it.each(['queued', 'running', 'completed', 'partial', 'failed', 'cancelled'])(
    'renders the %s job status',
    (status) => {
      render(<StatusBadge status={status} />);

      expect(screen.getByText(status)).toBeInTheDocument();
    },
  );

  it.each(['pending', 'ok', 'skipped'])('renders the %s stage status', (status) => {
    render(<StatusBadge status={status} />);

    expect(screen.getByText(status)).toBeInTheDocument();
  });

  it('renders a skipped stage neutrally rather than as a success', () => {
    // A skipped stage is an absence of analysis. Colouring it green would make a job
    // that ran two of seven stages look complete.
    const { container: skipped } = render(<StatusBadge status="skipped" />);
    const { container: ok } = render(<StatusBadge status="ok" />);

    expect(skipped.firstElementChild?.className).toContain('muted');
    expect(ok.firstElementChild?.className).not.toContain('muted');
  });

  it('renders a failure as the most alarming status', () => {
    const { container } = render(<StatusBadge status="failed" />);

    expect(container.firstElementChild?.className).toContain('severity-critical');
  });

  it('falls back to neutral for an unknown status', () => {
    const { container } = render(<StatusBadge status="reticulating" />);

    expect(screen.getByText('reticulating')).toBeInTheDocument();
    expect(container.firstElementChild?.className).toContain('muted');
  });
});

describe('SeverityBadge', () => {
  it.each(['info', 'low', 'medium', 'high', 'critical'])('renders %s', (severity) => {
    render(<SeverityBadge severity={severity} />);

    expect(screen.getByText(severity)).toBeInTheDocument();
  });

  it('escalates its colour with the severity', () => {
    const { container: info } = render(<SeverityBadge severity="info" />);
    const { container: critical } = render(<SeverityBadge severity="critical" />);

    expect(info.firstElementChild?.className).toContain('severity-info');
    expect(critical.firstElementChild?.className).toContain('severity-critical');
  });

  it('falls back to neutral for an unknown severity', () => {
    const { container } = render(<SeverityBadge severity="spicy" />);

    expect(screen.getByText('spicy')).toBeInTheDocument();
    expect(container.firstElementChild?.className).toContain('muted');
  });
});

describe('colour tables are kept separate', () => {
  it('a completed job and a benign tier do not share a colour by accident', () => {
    // A "completed" pipeline next to a "critical" verdict must not read as reassuring;
    // the status is a fact about the pipeline and the tier is a judgement about the
    // sample, so they are coloured from different tables on purpose.
    const { container: completed } = render(<StatusBadge status="completed" />);
    const { container: critical } = render(<TierBadge tier="critical" />);

    expect(completed.firstElementChild?.className).toContain('severity-low');
    expect(critical.firstElementChild?.className).toContain('severity-critical');
  });
});
