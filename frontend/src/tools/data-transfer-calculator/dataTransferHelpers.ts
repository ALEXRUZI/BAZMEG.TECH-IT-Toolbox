import type { TransferSpeedUnit, TransferTimeUnit } from './dataTransferTypes';

export const transferSpeedUnits: Record<TransferSpeedUnit, number> = {
  bps: 1,
  Kbps: 1_000,
  Mbps: 1_000_000,
  Gbps: 1_000_000_000,
  'B/s': 8,
  'KB/s': 8_000,
  'MB/s': 8_000_000,
  'GB/s': 8_000_000_000,
};

export const transferTimeUnits: Record<TransferTimeUnit, number> = {
  seconds: 1,
  minutes: 60,
  hours: 3_600,
  days: 86_400,
};

export const dataTransferExamples = {
  size: '500',
  speed: '15',
  time: '4.44',
};

export function formatDuration(totalSeconds: number) {
  const roundedSeconds = Math.round(totalSeconds);
  const days = Math.floor(roundedSeconds / 86_400);
  const hours = Math.floor((roundedSeconds % 86_400) / 3_600);
  const minutes = Math.floor((roundedSeconds % 3_600) / 60);
  const seconds = roundedSeconds % 60;
  const parts: string[] = [];

  if (days) parts.push(`${days} d`);
  if (hours) parts.push(`${hours} h`);
  if (minutes) parts.push(`${minutes} min`);
  if (seconds || !parts.length) parts.push(`${seconds} sec`);

  return parts.join(' ');
}
