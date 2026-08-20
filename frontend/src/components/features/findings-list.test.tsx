// Findings are the product, and the ordering and expansion are what make them usable.
// Two behaviours here are safety properties rather than conveniences: worst-first
// ordering (findings arrive in engine order, which no analyst wants to read), and the
// empty state saying explicitly that no findings is not a clean verdict.

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { FindingsList } from './findings-list';
import type { Finding } from '@/lib/api/types';

// No `as Finding` cast: the cast is what let an earlier version of this fixture omit
// `mitre`, which the backend always sends and the row reads unguarded.
function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    finding_id: 'f-1',
    source_engine: 'static',
    type: 'permission',
    severity: 'high',
    confidence: 0.9,
    detail: 'Requests a dangerous permission.',
    provenance: {},
    mitre: [],
    owasp_mobile: [],
    ...overrides,
  };
}

/** The severity badge on each row, in render order. */
function renderedSeverities(): string[] {
  return screen
    .getAllByRole('button', { expanded: false })
    .map((row) => row.textContent ?? '')
    .map((text) => /(critical|high|medium|low|info)/.exec(text)?.[1] ?? '')
    .filter(Boolean);
}

describe('ordering', () => {
  it('renders worst first regardless of the order it was given', async () => {
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'a', severity: 'low' }),
          finding({ finding_id: 'b', severity: 'critical' }),
          finding({ finding_id: 'c', severity: 'medium' }),
          finding({ finding_id: 'd', severity: 'info' }),
          finding({ finding_id: 'e', severity: 'high' }),
        ]}
      />,
    );

    expect(renderedSeverities()).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('breaks ties on the finding id so the order is stable across polls', async () => {
    // The job page polls; a re-sort that reshuffles equal-severity rows would make
    // the list jump under the reader's cursor.
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'zebra', severity: 'high' }),
          finding({ finding_id: 'alpha', severity: 'high' }),
        ]}
      />,
    );

    const rows = screen.getAllByRole('button', { expanded: false });
    await userEvent.click(rows[0]);
    expect(screen.getByText('alpha')).toBeInTheDocument();
  });

  it('places an unrecognised severity last rather than first', async () => {
    // An engine emitting a new severity must not push a critical finding down.
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'a', severity: 'wat' as never }),
          finding({ finding_id: 'b', severity: 'critical' }),
        ]}
      />,
    );

    expect(renderedSeverities()[0]).toBe('critical');
  });
});

describe('empty state', () => {
  it('says that no findings is not the same as a clean verdict', () => {
    // The most consequential sentence in the UI. A blank list reads as reassurance,
    // and a job where every stage was skipped produces exactly that.
    render(<FindingsList findings={[]} />);

    expect(screen.getByText(/no findings/i)).toBeInTheDocument();
    expect(screen.getByText(/not the same as a clean verdict/i)).toBeInTheDocument();
  });

  it('points the reader at the pipeline stages', () => {
    render(<FindingsList findings={[]} />);

    expect(screen.getByText(/skipped or failed/i)).toBeInTheDocument();
  });
});

describe('counts and filters', () => {
  it('reports the total in the heading', () => {
    render(
      <FindingsList findings={[finding({ finding_id: 'a' }), finding({ finding_id: 'b' })]} />,
    );

    expect(screen.getByText('Findings (2)')).toBeInTheDocument();
  });

  it('offers a chip only for severities that are present', () => {
    render(<FindingsList findings={[finding({ severity: 'critical' })]} />);

    expect(screen.getByRole('button', { name: /critical 1/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^low/i })).not.toBeInTheDocument();
  });

  it('filters to one severity when its chip is clicked', async () => {
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'a', severity: 'critical' }),
          finding({ finding_id: 'b', severity: 'low' }),
        ]}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: /critical 1/i }));

    expect(renderedSeverities()).toEqual(['critical']);
  });

  it('restores everything when All is clicked', async () => {
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'a', severity: 'critical' }),
          finding({ finding_id: 'b', severity: 'low' }),
        ]}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: /critical 1/i }));
    await userEvent.click(screen.getByRole('button', { name: /all 2/i }));

    expect(renderedSeverities()).toHaveLength(2);
  });

  it('keeps the total in the heading while a filter is applied', async () => {
    // The heading is the sample's finding count, not the current view's — a reader who
    // filtered to critical still needs to know how much else there is.
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'a', severity: 'critical' }),
          finding({ finding_id: 'b', severity: 'low' }),
        ]}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: /critical 1/i }));

    expect(screen.getByText('Findings (2)')).toBeInTheDocument();
  });
});

describe('provenance expansion', () => {
  it('a row starts collapsed', () => {
    render(<FindingsList findings={[finding()]} />);

    expect(screen.getByRole('button', { expanded: false })).toBeInTheDocument();
  });

  it('expanding a row reveals the evidence behind the claim', async () => {
    // The expansion is what turns an assertion into something an analyst can check
    // and a regulator can be shown.
    render(
      <FindingsList
        findings={[
          finding({
            finding_id: 'perm:BIND_ACCESSIBILITY_SERVICE',
            provenance: { extractor: 'permissions', locator: 'AndroidManifest.xml' },
          }),
        ]}
      />,
    );

    await userEvent.click(screen.getByRole('button', { expanded: false }));

    expect(screen.getByText('perm:BIND_ACCESSIBILITY_SERVICE')).toBeInTheDocument();
    expect(screen.getByRole('button', { expanded: true })).toBeInTheDocument();
  });

  it('collapses again on a second click', async () => {
    render(<FindingsList findings={[finding()]} />);

    const row = screen.getByRole('button', { expanded: false });
    await userEvent.click(row);
    await userEvent.click(screen.getByRole('button', { expanded: true }));

    expect(screen.getByRole('button', { expanded: false })).toBeInTheDocument();
  });

  it('expansion state is per row', async () => {
    render(
      <FindingsList findings={[finding({ finding_id: 'a' }), finding({ finding_id: 'b' })]} />,
    );

    await userEvent.click(screen.getAllByRole('button', { expanded: false })[0]);

    expect(screen.getAllByRole('button', { expanded: false })).toHaveLength(1);
    expect(screen.getAllByRole('button', { expanded: true })).toHaveLength(1);
  });

  it('a finding with no provenance still expands without crashing', async () => {
    // Not every engine records provenance for every finding, and the row must still
    // show the id and confidence.
    render(<FindingsList findings={[finding({ provenance: {} })]} />);

    await userEvent.click(screen.getByRole('button', { expanded: false }));

    expect(screen.getByText('f-1')).toBeInTheDocument();
  });
});

describe('row content', () => {
  it('shows the severity, the type, and which engine said it', () => {
    // The engine matters: the same claim from static analysis and from the LLM carries
    // different weight.
    render(
      <FindingsList findings={[finding({ type: 'dangerous_api', source_engine: 'code_intel' })]} />,
    );

    const row = screen.getByRole('button', { expanded: false });
    expect(within(row).getByText('high')).toBeInTheDocument();
    expect(within(row).getByText('dangerous api')).toBeInTheDocument();
    expect(within(row).getByText('code_intel')).toBeInTheDocument();
  });

  it('renders a finding with no detail', () => {
    render(<FindingsList findings={[finding({ detail: null })]} />);

    expect(screen.getByRole('button', { expanded: false })).toBeInTheDocument();
  });

  it('two findings with the same id from different engines both render', () => {
    // The row key is engine + id; keying on id alone would silently drop one, and
    // "perm:READ_SMS" is exactly the kind of id two engines both produce.
    render(
      <FindingsList
        findings={[
          finding({ finding_id: 'perm:READ_SMS', source_engine: 'static' }),
          finding({ finding_id: 'perm:READ_SMS', source_engine: 'ai_orchestrator' }),
        ]}
      />,
    );

    expect(screen.getAllByRole('button', { expanded: false })).toHaveLength(2);
  });
});
