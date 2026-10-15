import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AboutPage, isPrereleaseVersion } from '../../pages/AboutPage';

describe('TraceSleuth About and attribution', () => {
  it('shows the authoritative repository VERSION instead of inherited UI metadata', () => {
    render(<AboutPage />);
    expect(screen.getByRole('heading', { name: 'About TraceSleuth' })).toBeInTheDocument();
    expect(screen.getByText(__TRACESLEUTH_VERSION__)).toBeInTheDocument();
    expect(screen.queryByText('SD-WAN Triage v4.3.0')).not.toBeInTheDocument();
  });

  it('retains explicit upstream authorship without implying endorsement', () => {
    render(<AboutPage />);
    expect(screen.getByText(/MIT-licensed SD-WAN Triage project by Gocisse/)).toBeInTheDocument();
    expect(screen.getByText(/no endorsement by the original author/)).toBeInTheDocument();
    const origin = screen.getByRole('link', { name: /Original SD-WAN Triage project/ });
    expect(origin).toHaveAttribute('href', 'https://github.com/gocisse/sdwan-triage');
    expect(origin).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByRole('link', { name: /Exact upstream baseline and attribution/ }))
      .toHaveAttribute('href', 'https://github.com/DanielDietz-de/TraceSleuth/blob/main/UPSTREAM.md');
  });

  it.each([
    '0.2.0', '0.9.0', '0.9.0-rc.1', '1.0.0-rc.1',
    '2.0.0-beta.3+build.9',
  ])('labels %s as prerelease', (version) => {
    expect(isPrereleaseVersion(version)).toBe(true);
  });

  it.each([
    '1.0.0', '1.0.0+build-experimental', '2.0.0',
  ])('does not mistake stable %s for prerelease', (version) => {
    expect(isPrereleaseVersion(version)).toBe(false);
  });

  it('does not claim prerelease development builds are production ready', () => {
    render(<AboutPage />);
    if (isPrereleaseVersion(__TRACESLEUTH_VERSION__)) {
      expect(screen.getByRole('status')).toHaveTextContent('not production-ready');
    } else {
      expect(screen.queryByRole('status')).not.toBeInTheDocument();
    }
  });
});
