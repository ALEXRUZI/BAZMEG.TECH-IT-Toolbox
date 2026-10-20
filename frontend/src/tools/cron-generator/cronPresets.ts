export const cronPresets = [
  { label: 'Every 5 minutes', value: 'every-5-minutes', fields: ['*/5', '*', '*', '*', '*'] },
  { label: 'Every 15 minutes', value: 'every-15-minutes', fields: ['*/15', '*', '*', '*', '*'] },
  { label: 'Every 30 minutes', value: 'every-30-minutes', fields: ['*/30', '*', '*', '*', '*'] },
  { label: 'Hourly', value: 'hourly', fields: ['0', '*', '*', '*', '*'] },
  { label: 'Every 4 hours', value: 'every-4-hours', fields: ['0', '*/4', '*', '*', '*'] },
  { label: 'Every 8 hours', value: 'every-8-hours', fields: ['0', '*/8', '*', '*', '*'] },
  { label: 'Daily at midnight', value: 'daily-midnight', fields: ['0', '0', '*', '*', '*'] },
  { label: 'Daily at 02:00', value: 'daily-2', fields: ['0', '2', '*', '*', '*'] },
  { label: 'Weekly on Sunday', value: 'weekly-sunday', fields: ['0', '0', '*', '*', '0'] },
  { label: 'Monthly on the 1st', value: 'monthly-first', fields: ['0', '0', '1', '*', '*'] },
];

export const cronFieldLabels = ['Minute', 'Hour', 'Day of month', 'Month', 'Day of week'];

export const cronFieldRanges = [
  { min: 0, max: 59 },
  { min: 0, max: 23 },
  { min: 1, max: 31 },
  { min: 1, max: 12 },
  { min: 0, max: 7 },
];
