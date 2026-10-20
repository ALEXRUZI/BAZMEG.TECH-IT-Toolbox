import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import type { DataSizeUnit } from '../information-shared/informationUnits';
import { dataSizeUnits, dataSizeUnitLabels, dataSizeUnitList } from '../information-shared/informationUnits';
import { parsePositiveNumber, positiveProductRatio, numericRangeError, formatCalculatedValue } from '../information-shared/informationFormatting';
import type { DataTransferMode, TransferSpeedUnit, TransferTimeUnit } from './dataTransferTypes';
import { transferSpeedUnits, transferTimeUnits, dataTransferExamples, formatDuration } from './dataTransferHelpers';

export function DataTransferCalculator() {
  const [mode, setMode] = useState<DataTransferMode>('time');
  const [size, setSize] = useState(dataTransferExamples.size);
  const [isSizeExample, setIsSizeExample] = useState(true);
  const [sizeUnit, setSizeUnit] = useState<DataSizeUnit>('MB');
  const [speed, setSpeed] = useState(dataTransferExamples.speed);
  const [isSpeedExample, setIsSpeedExample] = useState(true);
  const [speedUnit, setSpeedUnit] = useState<TransferSpeedUnit>('Mbps');
  const [time, setTime] = useState(dataTransferExamples.time);
  const [isTimeExample, setIsTimeExample] = useState(true);
  const [timeUnit, setTimeUnit] = useState<TransferTimeUnit>('minutes');

  const parsedSize = parsePositiveNumber(size);
  const parsedSpeed = parsePositiveNumber(speed);
  const parsedTime = parsePositiveNumber(time);
  const sizeBits = parsedSize ? parsedSize * dataSizeUnits[sizeUnit] : null;
  const speedBitsPerSecond = parsedSpeed ? parsedSpeed * transferSpeedUnits[speedUnit] : null;
  const timeSeconds = parsedTime ? parsedTime * transferTimeUnits[timeUnit] : null;
  const sizeError = mode !== 'size' && !parsedSize ? 'Enter a file size greater than zero.' : '';
  const speedError = mode !== 'speed' && !parsedSpeed ? 'Enter a transfer speed greater than zero.' : '';
  const timeError = mode !== 'time' && !parsedTime ? 'Enter a transfer time greater than zero.' : '';

  let resultTitle = 'Transfer time';
  let resultOutput = '';
  let detailOutput = '';

  if (mode === 'time' && parsedSize && parsedSpeed) {
    const numerators = [parsedSize, dataSizeUnits[sizeUnit]];
    const denominators = [parsedSpeed, transferSpeedUnits[speedUnit]];
    const ordinarySeconds = Number.isFinite(sizeBits) && Number.isFinite(speedBitsPerSecond)
      ? (sizeBits ?? 0) / (speedBitsPerSecond ?? 1)
      : 0;
    const resultSeconds = positiveProductRatio(numerators, denominators, ordinarySeconds);
    resultOutput = numericRangeError(resultSeconds) || formatDuration(resultSeconds);
    detailOutput = [
      formatCalculatedValue(resultSeconds, 'seconds'),
      formatCalculatedValue(positiveProductRatio(numerators, [...denominators, 60], ordinarySeconds / 60), 'minutes'),
      formatCalculatedValue(positiveProductRatio(numerators, [...denominators, 3_600], ordinarySeconds / 3_600), 'hours'),
    ].join('\n');
  }

  if (mode === 'speed' && parsedSize && parsedTime) {
    const numerators = [parsedSize, dataSizeUnits[sizeUnit]];
    const denominators = [parsedTime, transferTimeUnits[timeUnit]];
    const ordinarySpeed = Number.isFinite(sizeBits) && Number.isFinite(timeSeconds)
      ? (sizeBits ?? 0) / (timeSeconds ?? 1)
      : 0;
    const resultBitsPerSecond = positiveProductRatio(numerators, denominators, ordinarySpeed);
    const resultMbps = positiveProductRatio(numerators, [...denominators, 1_000_000], ordinarySpeed / 1_000_000);
    const resultMegabytes = positiveProductRatio(numerators, [...denominators, 8_000_000], ordinarySpeed / 8_000_000);
    resultTitle = 'Required transfer speed';
    resultOutput = formatCalculatedValue(resultMbps, 'Mbps');
    detailOutput = [
      formatCalculatedValue(resultBitsPerSecond, 'bps'),
      formatCalculatedValue(resultMbps, 'Mbps'),
      formatCalculatedValue(resultMegabytes, 'MB/s'),
    ].join('\n');
  }

  if (mode === 'size' && parsedSpeed && parsedTime) {
    const numerators = [parsedSpeed, transferSpeedUnits[speedUnit], parsedTime, transferTimeUnits[timeUnit]];
    const ordinaryBits = (speedBitsPerSecond ?? 0) * (timeSeconds ?? 0);
    const resultInUnit = (unit: DataSizeUnit) =>
      positiveProductRatio(numerators, [dataSizeUnits[unit]], ordinaryBits / dataSizeUnits[unit]);
    resultTitle = 'Transferable data size';
    resultOutput = formatCalculatedValue(resultInUnit('GB'), 'GB');
    detailOutput = [
      formatCalculatedValue(resultInUnit('MB'), 'MB'),
      formatCalculatedValue(resultInUnit('GB'), 'GB'),
      formatCalculatedValue(resultInUnit('TB'), 'TB'),
      formatCalculatedValue(resultInUnit('PB'), 'PB'),
      formatCalculatedValue(resultInUnit('PiB'), 'PiB'),
    ].join('\n');
  }

  const hasError = Boolean(sizeError || speedError || timeError);

  return (
    <Panel title="Data Transfer Calculator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Estimate transfer time, required speed, or transferable data size using file size, bandwidth, and duration.
      </p>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        <button
          className={`rounded-2xl border p-4 text-left transition ${
            mode === 'time'
              ? 'border-emerald-400/50 bg-emerald-950/30'
              : 'border-white/10 bg-zinc-950/60 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => setMode('time')}
        >
          <p className="text-sm font-semibold text-zinc-100">Find time</p>
          <p className="mt-2 text-xs leading-5 text-zinc-400">File size / transfer speed</p>
        </button>
        <button
          className={`rounded-2xl border p-4 text-left transition ${
            mode === 'speed'
              ? 'border-emerald-400/50 bg-emerald-950/30'
              : 'border-white/10 bg-zinc-950/60 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => setMode('speed')}
        >
          <p className="text-sm font-semibold text-zinc-100">Find speed</p>
          <p className="mt-2 text-xs leading-5 text-zinc-400">File size / transfer time</p>
        </button>
        <button
          className={`rounded-2xl border p-4 text-left transition ${
            mode === 'size'
              ? 'border-emerald-400/50 bg-emerald-950/30'
              : 'border-white/10 bg-zinc-950/60 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => setMode('size')}
        >
          <p className="text-sm font-semibold text-zinc-100">Find size</p>
          <p className="mt-2 text-xs leading-5 text-zinc-400">Speed x transfer time</p>
        </button>
      </div>
      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_0.9fr]">
        <div className="grid gap-4">
          {mode !== 'size' && (
            <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
              <Field error={sizeError}>
                <Label>File size</Label>
                <FieldInput
                  className={inputClass(Boolean(sizeError), isSizeExample)}
                  placeholder={dataTransferExamples.size}
                  value={size}
                  onFocus={() => {
                    if (isSizeExample) {
                      setSize('');
                      setIsSizeExample(false);
                    }
                  }}
                  onChange={(event) => {
                    setSize(event.target.value);
                    setIsSizeExample(false);
                  }}
                  onBlur={() => {
                    if (!size.trim()) {
                      setSize(dataTransferExamples.size);
                      setIsSizeExample(true);
                    }
                  }}
                />
                <FieldError />
              </Field>
              <Field>
                <Label>File size unit</Label>
                <FieldSelect
                  className={inputClass()}
                  value={sizeUnit}
                  onChange={(event) => setSizeUnit(event.target.value as DataSizeUnit)}
                >
                  {dataSizeUnitList.map((unit) => (
                    <option key={unit} value={unit}>
                      {dataSizeUnitLabels[unit]}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
            </div>
          )}
          {mode !== 'speed' && (
            <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
              <Field error={speedError}>
                <Label>Transfer speed</Label>
                <FieldInput
                  className={inputClass(Boolean(speedError), isSpeedExample)}
                  placeholder={dataTransferExamples.speed}
                  value={speed}
                  onFocus={() => {
                    if (isSpeedExample) {
                      setSpeed('');
                      setIsSpeedExample(false);
                    }
                  }}
                  onChange={(event) => {
                    setSpeed(event.target.value);
                    setIsSpeedExample(false);
                  }}
                  onBlur={() => {
                    if (!speed.trim()) {
                      setSpeed(dataTransferExamples.speed);
                      setIsSpeedExample(true);
                    }
                  }}
                />
                <FieldError />
              </Field>
              <Field>
                <Label>Transfer speed unit</Label>
                <FieldSelect
                  className={inputClass()}
                  value={speedUnit}
                  onChange={(event) => setSpeedUnit(event.target.value as TransferSpeedUnit)}
                >
                  {Object.keys(transferSpeedUnits).map((unit) => (
                    <option key={unit} value={unit}>
                      {unit}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
            </div>
          )}
          {mode !== 'time' && (
            <div className="grid gap-4 sm:grid-cols-[1fr_160px]">
              <Field error={timeError}>
                <Label>Transfer time</Label>
                <FieldInput
                  className={inputClass(Boolean(timeError), isTimeExample)}
                  placeholder={dataTransferExamples.time}
                  value={time}
                  onFocus={() => {
                    if (isTimeExample) {
                      setTime('');
                      setIsTimeExample(false);
                    }
                  }}
                  onChange={(event) => {
                    setTime(event.target.value);
                    setIsTimeExample(false);
                  }}
                  onBlur={() => {
                    if (!time.trim()) {
                      setTime(dataTransferExamples.time);
                      setIsTimeExample(true);
                    }
                  }}
                />
                <FieldError />
              </Field>
              <Field>
                <Label>Transfer time unit</Label>
                <FieldSelect
                  className={inputClass()}
                  value={timeUnit}
                  onChange={(event) => setTimeUnit(event.target.value as TransferTimeUnit)}
                >
                  {Object.keys(transferTimeUnits).map((unit) => (
                    <option key={unit} value={unit}>
                      {unit}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
            </div>
          )}
        </div>
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-sm font-semibold text-zinc-200">{resultTitle}</p>
          {hasError ? (
            <p className="mt-3 text-sm leading-6 text-red-300">Enter the required values to calculate the result.</p>
          ) : (
            <>
              <p className="mt-3 font-mono text-xl font-semibold text-emerald-300">{resultOutput}</p>
              <CommandBlock>{detailOutput}</CommandBlock>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}
