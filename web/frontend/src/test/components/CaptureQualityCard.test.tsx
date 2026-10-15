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

  it('shows PCAPNG capture filters without implying STP/LACP observability', () => {
    render(<CaptureQualityCard quality={{
      ...good,
      format: 'pcapng',
      status: 'degraded',
      interfaces: [
        { section_index: 1, index: 0, name: 'uplink', link_type: 'Ethernet',
          filter: 'tcp port 443', snap_length: 65535, packet_count: 3 },
      ],
      capabilities: ['ethernet', 'vlan'],
    }} />);
    expect(screen.getByText(/Capture filters restrict protocol visibility/)).toBeInTheDocument();
    expect(screen.getByText(/tcp port 443/)).toBeInTheDocument();
    expect(screen.getByText('Capture quality: Degraded')).toBeInTheDocument();
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
  it('renders every interface-specific limitation even when codes repeat', () => {
    render(<CaptureQualityCard quality={{
      ...good,
      status: 'degraded',
      limitations: [
        { code: 'capture_reported_drops', severity: 'warning', count: 4,
          description: 'Capture section 0 interface 0 reported packet drops' },
        { code: 'capture_reported_drops', severity: 'warning', count: 9,
          description: 'Capture section 0 interface 1 reported packet drops' },
      ],
    }} />);
    expect(screen.getByText(/Capture section 0 interface 0 reported packet drops/)).toBeInTheDocument();
    expect(screen.getByText(/Capture section 0 interface 1 reported packet drops/)).toBeInTheDocument();
  });

});
