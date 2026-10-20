import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CronGenerator } from '../src/tools/cron-generator/CronGenerator';
import { validateCronField } from '../src/tools/cron-generator/cronValidation';

function field(label: string, tag: 'input' | 'select' = 'input') {
  return screen.getByRole(tag === 'select' ? 'combobox' : 'textbox', { name: label });
}
function command() { return document.querySelector('pre')?.textContent; }
function custom() {
  render(<CronGenerator />);
  fireEvent.click(screen.getByRole('button', { name: 'Custom schedule' }));
}

describe('five-field numeric cron regression (not Quartz)', () => {
  const controlError = 'Cron schedule fields must not contain control characters or line separators.';

  // Test raw values directly: single-line browser inputs may strip CR/LF.
  it.each(['*/5\n', '*/5\r', '\n*/5', '5\n', '*\n', '*/5\t', '*/5\u2028', '*/5\u2029', '*/5\0', '*/5\u007f', '*/2\n,3', '*/2\r,3', '*/2\t,3', '1\n/2', '1\r/2', '1\n-5'])('rejects raw schedule control characters before trimming %j', (value) => {
    expect(validateCronField(value, 0, 59, 'Minute')).toBe(controlError);
  });

  it('rejects every C0/C1 control character and DEL anywhere in a field', () => {
    for (const code of [...Array.from({ length: 32 }, (_, index) => index), ...Array.from({ length: 33 }, (_, index) => index + 127)]) {
      const character = String.fromCharCode(code);
      for (const value of [`${character}*/5`, `*/${character}5`, `*/5${character}`]) {
        expect(validateCronField(value, 0, 59, 'Minute')).toBe(controlError);
      }
    }
  });

  it.each(['*/5', ' 5 '])('preserves valid raw schedule %j', (value) => {
    expect(validateCronField(value, 0, 59, 'Minute')).toBeNull();
  });

  it.each(['*/5\t', '*/5\0', '*/5\u007f', '*/5\u2028', '*/5\u2029'])('hides output and Copy with an accessible control-character error and recovers %j', (value) => {
    custom();
    const minute = field('Minute');
    fireEvent.change(minute, { target: { value } });
    expect(minute).toHaveValue(value);
    expect(minute).toHaveAttribute('aria-invalid', 'true');
    expect(minute).toHaveAccessibleDescription(controlError);
    expect(screen.getByText(controlError)).toBeVisible();
    expect(document.querySelector('pre')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Copy' })).toBeNull();
    fireEvent.change(minute, { target: { value: '*/5' } });
    expect(minute).not.toHaveAttribute('aria-invalid', 'true');
    expect(command()).toBe('*/5 2 * * * /usr/local/bin/backup.sh');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeVisible();
  });

  it('defaults to daily 02:00 with the sample command', () => {
    render(<CronGenerator />);
    expect(command()).toBe('0 2 * * * /usr/local/bin/backup.sh');
    expect(screen.getByRole('combobox')).toHaveValue('daily-2');
  });

  it.each([
    ['every-5-minutes', '*/5 * * * *'], ['every-15-minutes', '*/15 * * * *'], ['every-30-minutes', '*/30 * * * *'],
    ['hourly', '0 * * * *'], ['every-4-hours', '0 */4 * * *'], ['every-8-hours', '0 */8 * * *'],
    ['daily-midnight', '0 0 * * *'], ['daily-2', '0 2 * * *'], ['weekly-sunday', '0 0 * * 0'], ['monthly-first', '0 0 1 * *'],
  ])('preserves preset %s', (preset, expression) => {
    render(<CronGenerator />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: preset } });
    expect(command()).toBe(`${expression} /usr/local/bin/backup.sh`);
  });

  it.each([
    ['Minute', '*', '* 2 * * *'], ['Minute', '0', '0 2 * * *'], ['Minute', '59', '59 2 * * *'],
    ['Hour', '0', '0 0 * * *'], ['Hour', '23', '0 23 * * *'],
    ['Day of month', '1', '0 2 1 * *'], ['Day of month', '31', '0 2 31 * *'],
    ['Month', '1', '0 2 * 1 *'], ['Month', '12', '0 2 * 12 *'],
    ['Day of week', '0', '0 2 * * 0'], ['Day of week', '7', '0 2 * * 7'],
    ['Minute', '1-5', '1-5 2 * * *'], ['Minute', '1,15,59', '1,15,59 2 * * *'],
    ['Minute', '*/1', '*/1 2 * * *'], ['Minute', '*/5', '*/5 2 * * *'], ['Minute', '*/15', '*/15 2 * * *'], ['Minute', '1-10/2', '1-10/2 2 * * *'],
    ['Minute', '*/5,1-10/2,5/2', '*/5,1-10/2,5/2 2 * * *'],
    ['Minute', '*/9007199254740991', '*/9007199254740991 2 * * *'],
    // Existing validator accepts numeric steps, wildcard lists, equal range ends
    // and ordinary surrounding ASCII spaces (which remain in output).
    ['Minute', '5/2', '5/2 2 * * *'], ['Minute', '*,1', '*,1 2 * * *'],
    ['Minute', '1-1', '1-1 2 * * *'], ['Minute', ' 5 ', ' 5  2 * * *'],
    ['Minute', '*/999', '*/999 2 * * *'],
  ])('preserves %s expression %s', (label, value, expression) => {
    custom();
    fireEvent.change(field(label), { target: { value } });
    expect(command()).toBe(`${expression} /usr/local/bin/backup.sh`);
  });

  it.each([
    ['Minute', '60', 'Allowed range is 0-59.'], ['Hour', '24', 'Allowed range is 0-23.'],
    ['Day of month', '0', 'Allowed range is 1-31.'], ['Day of month', '32', 'Allowed range is 1-31.'],
    ['Month', '0', 'Allowed range is 1-12.'], ['Month', '13', 'Allowed range is 1-12.'],
    ['Day of week', '8', 'Allowed range is 0-7.'], ['Minute', '5-1', 'Range start must be smaller than range end.'],
    ...['*/0', '*/x', '*/-1', '*/1.5', '*/abc', '*/Infinity', '*/NaN', '*/1e309', `*/${'9'.repeat(309)}`, '*/9007199254740992', '*/9007199254740993', '*/1 2', '*/ 2', '*/', '1,*/0', '*/5,1/'].map((value) => ['Minute', value, 'Step must be a positive safe integer (1-9007199254740991).']),
    ['Minute', '1/2/3', 'Use values like *, */5, 1, 1-5, or 1-10/2.'],
    ['Minute', '1,', 'Use values like *, */5, 1, 1-5, or 1-10/2.'],
    ['Minute', 'MON', 'Use numbers, ranges, lists, wildcards, or steps.'],
    ['Minute', '-1', 'Use numbers, ranges, lists, wildcards, or steps.'],
    ['Minute', '1.5', 'Use numbers, ranges, lists, wildcards, or steps.'],
    ['Minute', '?', 'Use numbers, ranges, lists, wildcards, or steps.'],
    ['Minute', '0 0 * * *', 'Use numbers, ranges, lists, wildcards, or steps.'],
    ['Minute', '', 'Minute is required. Use a value between 0 and 59, or * for every value.'],
    ['Hour', '', 'Hour is required. Use a value between 0 and 23, or * for every value.'],
    ['Day of month', '', 'Day of month is required. Use a value between 1 and 31, or * for every value.'],
    ['Month', '', 'Month is required. Use a value between 1 and 12, or * for every value.'],
    ['Day of week', '', 'Day of week is required. Use a value between 0 and 7, or * for every value.'],
  ])('rejects %s input %j with its existing message', (label, value, message) => {
    custom();
    fireEvent.change(field(label), { target: { value } });
    expect(screen.getByText(message)).toBeVisible();
    expect(screen.getByText('Fix the cron field values before using the generated crontab line.')).toBeVisible();
    expect(document.querySelector('pre')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Copy' })).toBeNull();
    expect(field(label)).toHaveValue(value);
    expect(field(label)).toHaveAttribute('aria-invalid', 'true');
    expect(field(label)).toHaveAccessibleDescription(message);
    fireEvent.change(field(label), { target: { value: '*' } });
    expect(document.querySelector('pre')).not.toBeNull();
  });

  it('edits all five fields and restores the selected preset', () => {
    render(<CronGenerator />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'weekly-sunday' } });
    fireEvent.click(screen.getByRole('button', { name: 'Custom schedule' }));
    ['Minute', 'Hour', 'Day of month', 'Month', 'Day of week'].forEach((label, i) => {
      fireEvent.change(field(label), { target: { value: ['15', '8', '1', '6', '1-5'][i] } });
    });
    expect(command()).toBe('15 8 1 6 1-5 /usr/local/bin/backup.sh');
    fireEvent.click(screen.getByRole('button', { name: 'Preset schedule' }));
    expect(command()).toBe('0 0 * * 0 /usr/local/bin/backup.sh');
    fireEvent.click(screen.getByRole('button', { name: 'Custom schedule' }));
    expect(field('Minute')).toHaveValue('0');
    expect(field('Day of week')).toHaveValue('0');
  });

  it('preserves raw command text and empty-command restoration', () => {
    render(<CronGenerator />);
    const input = field('Command');
    fireEvent.focus(input);
    expect(command()).toBe('0 2 * * * <command>');
    fireEvent.change(input, { target: { value: '  echo test >> /tmp/log  ' } });
    expect(command()).toBe('0 2 * * *   echo test >> /tmp/log  ');
    fireEvent.change(input, { target: { value: '' } });
    expect(command()).toBe('0 2 * * * <command>');
    fireEvent.blur(input);
    expect(command()).toBe('0 2 * * * /usr/local/bin/backup.sh');
  });
});
