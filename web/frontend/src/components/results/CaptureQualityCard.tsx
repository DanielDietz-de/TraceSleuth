import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import type { CaptureQualitySummary } from '../../types';

interface CaptureQualityCardProps {
  quality?: CaptureQualitySummary;
}

// A capture-quality observation is about what is measurable in this file,
// not a claim that the live network has (or lacks) a given pathology.
export function CaptureQualityCard({ quality }: CaptureQualityCardProps) {
  if (!quality) return null;

  const degraded = quality.status === 'degraded';
  const limitations = quality.limitations ?? [];
  return (
    <section
      aria-label="Capture quality"
      className="rounded-xl border border-slate-700 bg-slate-800/60 p-4"
    >
      <div className="flex items-center gap-2 font-semibold text-slate-100">
        {degraded
          ? <AlertTriangle className="w-5 h-5 text-amber-400" aria-hidden="true" />
          : <CheckCircle2 className="w-5 h-5 text-green-400" aria-hidden="true" />}
        <span>Capture quality: {degraded ? 'Degraded' : 'Good'}</span>
      </div>
      <p className="mt-2 text-sm text-slate-400">
        {quality.format.toUpperCase()} &bull; {quality.packet_count.toLocaleString()} packets
        {' '} &bull; {quality.truncated_packets.toLocaleString()} truncated
        {' '} &bull; {quality.non_monotonic_timestamps.toLocaleString()} timestamp reversals
      </p>
      <p className="mt-1 text-xs text-slate-500">
        Observed link types: {quality.link_types.length ? quality.link_types.join(', ') : 'unknown'}
        {' '} &bull; SHA-256: <code>{quality.sha256.slice(0, 16)}…</code>
      </p>
      {limitations.length > 0 && (
        <ul className="mt-3 space-y-1 text-sm text-amber-200">
          {limitations.map(issue => (
            <li key={issue.code}>
              {issue.description}
              {issue.count ? ' (observed ' + issue.count.toLocaleString() + ' times)' : ''}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-xs text-slate-500">
        Capture limitations can reduce the reliability of downstream network conclusions.
      </p>
    </section>
  );
}
