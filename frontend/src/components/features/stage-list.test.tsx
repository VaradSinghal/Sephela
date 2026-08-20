// Per-stage progress. The reason a stage produced what it did is the point of the
// component: a skipped stage rendered as a grey badge and nothing else reads as "fine",
// but "dynamic analysis is disabled" and "the sandbox crashed" mean very different
// things for how much the verdict can be trusted.

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StageList } from './stage-list';
import type { StageDetail, StageInfo } from '@/lib/api/types';

function stage(overrides: Partial<StageDetail> = {}): StageDetail {
  return {
    engine: 'static',
    status: 'ok',
    started_at: '2026-08-20T10:00:00Z',
    finished_at: '2026-08-20T10:00:05Z',
    attempt: 1,
    error: null,
    engine_version: '1.0.0',
    ...overrides,
  } as StageDetail;
}

/** The stage labels in render order. */
function renderedLabels(): string[] {
  return [...document.querySelectorAll('.text-sm.font-medium')].map((n) => n.textContent ?? '');
}

describe('ordering', () => {
  it('renders stages in pipeline dependency order, not arrival order', () => {
    // A stage that has not started yet still has to appear where it will run, or the
    // list reorders itself as the job progresses.
    render(
      <StageList
        stages={[
          stage({ engine: 'reporting' }),
          stage({ engine: 'static' }),
          stage({ engine: 'scoring' }),
          stage({ engine: 'code_intel' }),
        ]}
        fallback={[]}
      />,
    );

    expect(renderedLabels()).toEqual([
      'Static analysis',
      'Code intelligence',
      'Risk scoring',
      'Report generation',
    ]);
  });

  it('places an unrecognised engine last rather than first', () => {
    render(
      <StageList
        stages={[stage({ engine: 'brand_new' }), stage({ engine: 'static' })]}
        fallback={[]}
      />,
    );

    expect(renderedLabels()[0]).toBe('Static analysis');
  });

  it('labels an unrecognised engine readably rather than dropping it', () => {
    render(<StageList stages={[stage({ engine: 'brand_new' })]} fallback={[]} />);

    expect(screen.getByText('brand new')).toBeInTheDocument();
  });

  it('gives every known stage a human label', () => {
    render(
      <StageList
        stages={[
          stage({ engine: 'static' }),
          stage({ engine: 'code_intel' }),
          stage({ engine: 'dynamic' }),
          stage({ engine: 'threat_intel' }),
          stage({ engine: 'ai_orchestrator' }),
          stage({ engine: 'scoring' }),
          stage({ engine: 'reporting' }),
        ]}
        fallback={[]}
      />,
    );

    // Notably the AI stage reads as what it does, not as its queue name.
    expect(screen.getByText('Multi-agent reasoning')).toBeInTheDocument();
    expect(renderedLabels()).toHaveLength(7);
  });
});

describe('the recorded reason', () => {
  it('shows why a stage was skipped', () => {
    // Without this, a skipped stage is indistinguishable from one that found nothing.
    render(
      <StageList
        stages={[
          stage({
            engine: 'dynamic',
            status: 'skipped',
            error: 'Dynamic analysis is disabled (SEPHELA_DYNAMIC_ENABLED).',
          }),
        ]}
        fallback={[]}
      />,
    );

    expect(screen.getByText(/SEPHELA_DYNAMIC_ENABLED/)).toBeInTheDocument();
  });

  it('shows why a stage failed, styled as a failure', () => {
    const { container } = render(
      <StageList
        stages={[stage({ status: 'failed', error: 'JADX not found on PATH.' })]}
        fallback={[]}
      />,
    );

    expect(screen.getByText('JADX not found on PATH.')).toBeInTheDocument();
    expect(container.innerHTML).toContain('text-destructive');
  });

  it('styles a skip reason neutrally rather than as an error', () => {
    // A deliberate skip is not a fault, and colouring it red would train readers to
    // ignore red.
    const { container } = render(
      <StageList stages={[stage({ status: 'skipped', error: 'Disabled.' })]} fallback={[]} />,
    );

    expect(container.innerHTML).not.toContain('text-destructive');
  });

  it('renders a stage with no recorded reason', () => {
    render(<StageList stages={[stage({ error: null })]} fallback={[]} />);

    expect(screen.getByText('ok')).toBeInTheDocument();
  });
});

describe('duration', () => {
  it('shows sub-second timings in milliseconds', () => {
    render(
      <StageList
        stages={[
          stage({
            started_at: '2026-08-20T10:00:00.000Z',
            finished_at: '2026-08-20T10:00:00.250Z',
          }),
        ]}
        fallback={[]}
      />,
    );

    expect(screen.getByText('250ms')).toBeInTheDocument();
  });

  it('shows seconds with one decimal', () => {
    render(
      <StageList
        stages={[
          stage({
            started_at: '2026-08-20T10:00:00.000Z',
            finished_at: '2026-08-20T10:00:05.500Z',
          }),
        ]}
        fallback={[]}
      />,
    );

    expect(screen.getByText('5.5s')).toBeInTheDocument();
  });

  it('shows minutes and seconds for a long stage', () => {
    // Decompiling a large APK is minutes, and "372.4s" is harder to read than "6m 12s".
    render(
      <StageList
        stages={[
          stage({ started_at: '2026-08-20T10:00:00Z', finished_at: '2026-08-20T10:06:12Z' }),
        ]}
        fallback={[]}
      />,
    );

    expect(screen.getByText('6m 12s')).toBeInTheDocument();
  });

  it('shows no duration for a stage still running', () => {
    render(<StageList stages={[stage({ status: 'running', finished_at: null })]} fallback={[]} />);

    expect(screen.getByText('running')).toBeInTheDocument();
    expect(screen.queryByText(/ms$/)).not.toBeInTheDocument();
  });

  it('shows no duration for a stage that never started', () => {
    render(
      <StageList
        stages={[stage({ status: 'pending', started_at: null, finished_at: null })]}
        fallback={[]}
      />,
    );

    expect(screen.getByText('pending')).toBeInTheDocument();
  });

  it('shows no duration when the timestamps are inverted', () => {
    // Clock skew across workers is real, and "-4000ms" is worse than nothing.
    render(
      <StageList
        stages={[
          stage({ started_at: '2026-08-20T10:00:05Z', finished_at: '2026-08-20T10:00:01Z' }),
        ]}
        fallback={[]}
      />,
    );

    expect(screen.queryByText(/-/)).not.toBeInTheDocument();
  });
});

describe('retries', () => {
  it('shows the attempt count when a stage was retried', () => {
    // A stage that only succeeded on its third try is worth a second look.
    render(<StageList stages={[stage({ attempt: 3 })]} fallback={[]} />);

    expect(screen.getByText('attempt 3')).toBeInTheDocument();
  });

  it('says nothing for a first attempt', () => {
    render(<StageList stages={[stage({ attempt: 1 })]} fallback={[]} />);

    expect(screen.queryByText(/attempt/)).not.toBeInTheDocument();
  });
});

describe('provenance', () => {
  it('shows the engine version that produced the stage', () => {
    // Evidence outlives the code that produced it, so a stored result has to say which
    // engine version made the call.
    render(<StageList stages={[stage({ engine_version: '1.4.2' })]} fallback={[]} />);

    expect(screen.getByText(/static v1\.4\.2/)).toBeInTheDocument();
  });
});

describe('fallback while the detail query is in flight', () => {
  it('renders the inline stages from the job when no detail has arrived', () => {
    // Otherwise the list blinks empty on every poll.
    const inline = [{ engine: 'static', status: 'ok' }] as StageInfo[];

    render(<StageList fallback={inline} />);

    expect(screen.getByText('Static analysis')).toBeInTheDocument();
  });

  it('prefers the detail once it arrives', () => {
    const inline = [{ engine: 'static', status: 'ok' }] as StageInfo[];

    render(<StageList stages={[stage({ engine: 'reporting' })]} fallback={inline} />);

    expect(screen.getByText('Report generation')).toBeInTheDocument();
    expect(screen.queryByText('Static analysis')).not.toBeInTheDocument();
  });

  it('falls back when the detail query returned an empty list', () => {
    // An empty array is "not loaded yet", not "no stages" — the job carries its own.
    const inline = [{ engine: 'static', status: 'ok' }] as StageInfo[];

    render(<StageList stages={[]} fallback={inline} />);

    expect(screen.getByText('Static analysis')).toBeInTheDocument();
  });

  it('says the pipeline has not started when there is nothing at all', () => {
    render(<StageList stages={[]} fallback={[]} />);

    expect(screen.getByText(/waiting for the pipeline/i)).toBeInTheDocument();
  });
});
