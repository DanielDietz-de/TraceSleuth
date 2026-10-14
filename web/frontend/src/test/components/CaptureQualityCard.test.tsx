import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CaptureQualityCard } from '../../components/results/CaptureQualityCard';
import type { CaptureQualitySummary } from '../../types';

const good: CaptureQualitySummary = {
  sha256: 'ab'.repeat(32),
  format: 'pcap',
  file_size_bytes: 1000,
  packet_count: 3,
  captured_bytes: 180,
  original_bytes: 180,
  truncated_packets: 0,
  truncation_rate: 0,
  non_monotonic_timestamps: 0,
  missing_timestamps: 0,
  large_timestamp_gaps: 0,
  duration_seconds: 1,
  link_types: ['Ethernet'],
  capabilities: ['ethernet'],
  limitations: [],
  status: 'good',
};

describe('capture quality panel', () => {
  it('does not invent quality for historical results', () => {
    const { container } = render(<CaptureQualityCard />);
    expect(container.firstChild).toBeNull();
  });

  it('shows measured metadata and no false fault warning for good captures', () => {
    render(<CaptureQualityCard quality={good} />);
    expect(screen.getByText('Capture quality: Good')).toBeInTheDocument();
    expect(screen.getByText(/3 packets/)).toBeInTheDocument();
    expect(screen.getByText(/Ethernet/)).toBeInTheDocument();
  });

  it('shows actionable capture limitations separately from network findings', () => {
    render(
      <CaptureQualityCard
        quality={{
          ...good,
          status: 'degraded',
          truncated_packets: 2,
          truncation_rate: 2 / 3,
          limitations: [{
            code: 'truncated_packets',
            severity: 'warning',
            count: 2,
            description: 'Packets were truncated during capture',
          }],
        }}
      />
    );
    expect(screen.getByText('Capture quality: Degraded')).toBeInTheDocument();
    expect(screen.getByText(/Packets were truncated/)).toBeInTheDocument();
  });
});
