import { useEffect, useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import { formatLocalDateTime, parseLocalDateTime } from './epochHelpers';
import type { DateOrder, TimeCycle } from './epochHelpers';

export function EpochTool() {
  const [now, setNow] = useState(() => new Date());
  const [timestamp, setTimestamp] = useState(() => Math.floor(Date.now() / 1000).toString());
  const [timestampUnit, setTimestampUnit] = useState<'seconds' | 'milliseconds'>('seconds');
  const [dateOrder, setDateOrder] = useState<DateOrder>('day-first');
  const [timeCycle, setTimeCycle] = useState<TimeCycle>('24h');
  const [dateInput, setDateInput] = useState(() => formatLocalDateTime(new Date(), 'day-first', '24h'));

  useEffect(() => {
    const intervalId = window.setInterval(() => setNow(new Date()), 1000);

    return () => window.clearInterval(intervalId);
  }, []);

  const parsedTimestamp = Number(timestamp);
  const hasNumericTimestamp = Boolean(timestamp.trim()) && Number.isFinite(parsedTimestamp);
  const timestampMilliseconds = timestampUnit === 'seconds' ? parsedTimestamp * 1000 : parsedTimestamp;
  const candidateTimestampDate =
    hasNumericTimestamp && Math.abs(timestampMilliseconds) <= 8_640_000_000_000_000
      ? new Date(timestampMilliseconds)
      : null;
  const timestampError = !hasNumericTimestamp
    ? 'Unix timestamp must be a number.'
    : !candidateTimestampDate || !Number.isFinite(candidateTimestampDate.getTime())
      ? 'Unix timestamp is outside the supported date range.'
      : '';
  const timestampDate = timestampError
    ? null
    : candidateTimestampDate;
  const dateInputDate = parseLocalDateTime(dateInput, dateOrder, timeCycle);
  const dateInputError = dateInputDate ? '' : `Use ${dateOrder === 'day-first' ? 'DD/MM/YYYY' : 'MM/DD/YYYY'} ${
    timeCycle === '24h' ? 'HH:mm:ss' : 'hh:mm:ss AM/PM'
  }.`;
  const convertedSeconds = dateInputDate && !dateInputError ? Math.floor(dateInputDate.getTime() / 1000).toString() : '';
  const convertedMilliseconds = dateInputDate && !dateInputError ? dateInputDate.getTime().toString() : '';
  const formatLabel = `${dateOrder === 'day-first' ? 'DD/MM/YYYY' : 'MM/DD/YYYY'} ${
    timeCycle === '24h' ? '24-hour' : '12-hour'
  } time with seconds`;
  const dateInputPlaceholder =
    dateOrder === 'day-first'
      ? timeCycle === '24h'
        ? '10/05/2026 14:30:00'
        : '10/05/2026 02:30:00 PM'
      : timeCycle === '24h'
        ? '05/10/2026 14:30:00'
        : '05/10/2026 02:30:00 PM';
  const toggleDateOrder = () => {
    const nextDateOrder = dateOrder === 'day-first' ? 'month-first' : 'day-first';
    const parsedDate = parseLocalDateTime(dateInput, dateOrder, timeCycle);

    setDateOrder(nextDateOrder);

    if (parsedDate) {
      setDateInput(formatLocalDateTime(parsedDate, nextDateOrder, timeCycle));
    }
  };
  const toggleTimeCycle = () => {
    const nextTimeCycle = timeCycle === '24h' ? '12h' : '24h';
    const parsedDate = parseLocalDateTime(dateInput, dateOrder, timeCycle);

    setTimeCycle(nextTimeCycle);

    if (parsedDate) {
      setDateInput(formatLocalDateTime(parsedDate, dateOrder, nextTimeCycle));
    }
  };

  return (
    <Panel title="Epoch & Unix timestamp conversion">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Convert Unix timestamps to readable local time, convert local date-time back to epoch values, and check the current
        time while troubleshooting logs or scheduled jobs.
      </p>
      <div className="mt-4 flex flex-wrap gap-3">
        <button
          className="rounded-full border border-white/10 bg-zinc-950/60 px-4 py-2 text-sm font-semibold text-zinc-200 transition hover:border-emerald-400/40 hover:text-emerald-200"
          type="button"
          onClick={toggleDateOrder}
        >
          {dateOrder === 'day-first' ? 'Use MM/DD/YYYY' : 'Use DD/MM/YYYY'}
        </button>
        <button
          className="rounded-full border border-white/10 bg-zinc-950/60 px-4 py-2 text-sm font-semibold text-zinc-200 transition hover:border-emerald-400/40 hover:text-emerald-200"
          type="button"
          onClick={toggleTimeCycle}
        >
          {timeCycle === '24h' ? 'Use 12-hour time' : 'Use 24-hour time'}
        </button>
      </div>
      <p className="mt-5 text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">Format in use: {formatLabel}</p>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">Current local time</p>
          <p className="mt-3 font-mono text-sm text-zinc-100">{formatLocalDateTime(now, dateOrder, timeCycle)}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">Unix seconds</p>
          <p className="mt-3 font-mono text-sm text-emerald-300">{Math.floor(now.getTime() / 1000)}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">Unix milliseconds</p>
          <p className="mt-3 font-mono text-sm text-emerald-300">{now.getTime()}</p>
        </div>
      </div>
      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <div>
          <h3 className="text-lg font-semibold">Timestamp to local time</h3>
          <div className="mt-4 grid gap-4 sm:grid-cols-[1fr_180px]">
            <Field error={timestampError}>
              <Label>Unix timestamp</Label>
              <FieldInput
                className={inputClass(Boolean(timestampError))}
                value={timestamp}
                onChange={(event) => setTimestamp(event.target.value)}
              />
              <FieldError />
            </Field>
            <Field>
              <Label>Unit</Label>
              <FieldSelect
                className={inputClass()}
                value={timestampUnit}
                onChange={(event) => setTimestampUnit(event.target.value as 'seconds' | 'milliseconds')}
              >
                <option value="seconds">Seconds</option>
                <option value="milliseconds">Milliseconds</option>
              </FieldSelect>
            </Field>
          </div>
          {!timestampError && timestampDate && (
            <CommandBlock>{`${formatLocalDateTime(timestampDate, dateOrder, timeCycle)}\n${timestampDate.toISOString()}`}</CommandBlock>
          )}
        </div>
        <div>
          <h3 className="text-lg font-semibold">Local time to timestamp</h3>
          <div className="mt-4">
            <Field error={dateInputError}>
              <Label>Local date and time</Label>
              <FieldInput
                className={inputClass(Boolean(dateInputError))}
                placeholder={dateInputPlaceholder}
                value={dateInput}
                onChange={(event) => setDateInput(event.target.value)}
              />
              <FieldError />
            </Field>
          </div>
          {!dateInputError && (
            <>
              <CommandBlock>{convertedSeconds}</CommandBlock>
              <CommandBlock>{convertedMilliseconds}</CommandBlock>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}
