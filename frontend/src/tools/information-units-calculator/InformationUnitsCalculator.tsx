import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import type { DataSizeUnit } from '../information-shared/informationUnits';
import { dataSizeUnits, dataSizeUnitLabels, dataSizeUnitList } from '../information-shared/informationUnits';
import { formatNumber, parsePositiveNumber, positiveProductRatio, formatCalculatedValue } from '../information-shared/informationFormatting';

export function InformationUnitsCalculator() {
  const exampleValue = '1024';
  const [inputValue, setInputValue] = useState(exampleValue);
  const [isInputExample, setIsInputExample] = useState(true);
  const [fromUnit, setFromUnit] = useState<DataSizeUnit>('MB');
  const [toUnit, setToUnit] = useState<DataSizeUnit>('MiB');
  const parsedValue = parsePositiveNumber(inputValue);
  const inputError = parsedValue ? '' : 'Enter a value greater than zero.';
  const convertedValue = parsedValue
    ? positiveProductRatio([parsedValue, dataSizeUnits[fromUnit]], [dataSizeUnits[toUnit]],
        (parsedValue * dataSizeUnits[fromUnit]) / dataSizeUnits[toUnit])
    : null;
  const bitsValue = parsedValue
    ? positiveProductRatio([parsedValue, dataSizeUnits[fromUnit]], [], parsedValue * dataSizeUnits[fromUnit])
    : null;
  const resultText = convertedValue === null ? '' : formatCalculatedValue(convertedValue, toUnit, 8);
  const rateResultText = convertedValue === null ? '' : formatCalculatedValue(convertedValue, `${toUnit}/s`, 8);
  const detailOutput =
    convertedValue === null
      ? ''
      : [
          `${formatNumber(parsedValue ?? 0, 8)} ${fromUnit}`,
          `= ${formatCalculatedValue(convertedValue, toUnit, 8)}`,
          `= ${formatCalculatedValue(bitsValue ?? 0, 'bits')}`,
        ].join('\n');
  const rateDetailOutput =
    convertedValue === null
      ? ''
      : [
          `${formatNumber(parsedValue ?? 0, 8)} ${fromUnit}/s`,
          `= ${formatCalculatedValue(convertedValue, `${toUnit}/s`, 8)}`,
          `= ${formatCalculatedValue(bitsValue ?? 0, 'bps')}`,
        ].join('\n');

  return (
    <Panel title="Units of information calculator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Convert between information units and matching per-second data-rate units using the same decimal and binary units
        as the Data Transfer Calculator.
      </p>
      <div className="mt-6 grid gap-6 xl:grid-cols-[1fr_0.9fr]">
        <div className="grid gap-4">
          <Field error={inputError}>
            <Label>Value</Label>
            <FieldInput
              className={inputClass(Boolean(inputError), isInputExample)}
              placeholder={exampleValue}
              value={inputValue}
              onFocus={() => {
                if (isInputExample) {
                  setInputValue('');
                  setIsInputExample(false);
                }
              }}
              onChange={(event) => {
                setInputValue(event.target.value);
                setIsInputExample(false);
              }}
              onBlur={() => {
                if (!inputValue.trim()) {
                  setInputValue(exampleValue);
                  setIsInputExample(true);
                }
              }}
            />
            <FieldError />
          </Field>
          <div className="grid gap-4 md:grid-cols-2">
            <Field>
              <Label>From</Label>
              <FieldSelect className={inputClass()} value={fromUnit} onChange={(event) => setFromUnit(event.target.value as DataSizeUnit)}>
                {dataSizeUnitList.map((unit) => (
                  <option key={unit} value={unit}>
                    {dataSizeUnitLabels[unit]}
                  </option>
                ))}
              </FieldSelect>
            </Field>
            <Field>
              <Label>To</Label>
              <FieldSelect className={inputClass()} value={toUnit} onChange={(event) => setToUnit(event.target.value as DataSizeUnit)}>
                {dataSizeUnitList.map((unit) => (
                  <option key={unit} value={unit}>
                    {dataSizeUnitLabels[unit]}
                  </option>
                ))}
              </FieldSelect>
            </Field>
          </div>
        </div>
        <div className="grid gap-4">
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <p className="text-sm font-semibold text-zinc-200">Converted value</p>
            {inputError ? (
              <p className="mt-3 text-sm leading-6 text-red-300">Enter a valid value to calculate the result.</p>
            ) : (
              <>
                <p className="mt-3 break-all font-mono text-xl font-semibold text-emerald-300">{resultText}</p>
                <CommandBlock>{detailOutput}</CommandBlock>
              </>
            )}
          </div>
          <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <p className="text-sm font-semibold text-zinc-200">Converted value per second</p>
            {inputError ? (
              <p className="mt-3 text-sm leading-6 text-red-300">Enter a valid value to calculate the result.</p>
            ) : (
              <>
                <p className="mt-3 break-all font-mono text-xl font-semibold text-emerald-300">{rateResultText}</p>
                <CommandBlock>{rateDetailOutput}</CommandBlock>
              </>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}
