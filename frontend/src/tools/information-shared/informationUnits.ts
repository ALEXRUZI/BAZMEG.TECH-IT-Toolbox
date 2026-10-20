export type DataSizeUnit =
  | 'b'
  | 'Kb'
  | 'Mb'
  | 'Gb'
  | 'Tb'
  | 'Pb'
  | 'B'
  | 'KB'
  | 'MB'
  | 'GB'
  | 'TB'
  | 'PB'
  | 'Kib'
  | 'Mib'
  | 'Gib'
  | 'Tib'
  | 'Pib'
  | 'KiB'
  | 'MiB'
  | 'GiB'
  | 'TiB'
  | 'PiB';

export const dataSizeUnits: Record<DataSizeUnit, number> = {
  b: 1,
  Kb: 1_000,
  Mb: 1_000_000,
  Gb: 1_000_000_000,
  Tb: 1_000_000_000_000,
  Pb: 1_000_000_000_000_000,
  B: 8,
  KB: 8_000,
  MB: 8_000_000,
  GB: 8_000_000_000,
  TB: 8_000_000_000_000,
  PB: 8_000_000_000_000_000,
  Kib: 1_024,
  Mib: 1_048_576,
  Gib: 1_073_741_824,
  Tib: 1_099_511_627_776,
  Pib: 1_125_899_906_842_624,
  KiB: 8_192,
  MiB: 8_388_608,
  GiB: 8_589_934_592,
  TiB: 8_796_093_022_208,
  PiB: 9_007_199_254_740_992,
};

export const dataSizeUnitLabels: Record<DataSizeUnit, string> = {
  b: 'b (bits)',
  Kb: 'Kb (Kilobits)',
  Mb: 'Mb (Megabits)',
  Gb: 'Gb (Gigabits)',
  Tb: 'Tb (Terabits)',
  Pb: 'Pb (Petabits)',
  B: 'B (Bytes)',
  KB: 'KB (Kilobytes)',
  MB: 'MB (Megabytes)',
  GB: 'GB (Gigabytes)',
  TB: 'TB (Terabytes)',
  PB: 'PB (Petabytes)',
  Kib: 'Kib (Kibibits)',
  Mib: 'Mib (Mebibits)',
  Gib: 'Gib (Gibibits)',
  Tib: 'Tib (Tebibits)',
  Pib: 'Pib (Pebibits)',
  KiB: 'KiB (Kibibytes)',
  MiB: 'MiB (Mebibytes)',
  GiB: 'GiB (Gibibytes)',
  TiB: 'TiB (Tebibytes)',
  PiB: 'PiB (Pebibytes)',
};

export const dataSizeUnitList = Object.keys(dataSizeUnits) as DataSizeUnit[];
