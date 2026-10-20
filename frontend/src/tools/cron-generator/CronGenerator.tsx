import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldInput, FieldSelect, FieldError } from '../../components/Panel';
import { clearExampleValue, restoreExampleValue } from '../../components/inputExamples';
import { validateCronField } from './cronValidation';
import { cronFieldRanges, cronFieldLabels, cronPresets } from './cronPresets';

export function CronGenerator() {
  const commandExample = '/usr/local/bin/backup.sh';
  const [useCustomSchedule, setUseCustomSchedule] = useState(false);
  const [preset, setPreset] = useState('daily-2');
  const [fields, setFields] = useState(['0', '2', '*', '*', '*']);
  const [command, setCommand] = useState(commandExample);
  const fieldErrors = fields.map((field, index) =>
    validateCronField(field, cronFieldRanges[index].min, cronFieldRanges[index].max, cronFieldLabels[index]),
  );
  const hasErrors = fieldErrors.some(Boolean);
  const crontabLine = `${fields.join(' ')} ${command || '<command>'}`;

  function selectPreset(nextPreset: string) {
    setPreset(nextPreset);
    const selectedPreset = cronPresets.find((cronPreset) => cronPreset.value === nextPreset);

    if (selectedPreset) {
      setFields(selectedPreset.fields);
    }
  }

  function updateField(index: number, value: string) {
    setUseCustomSchedule(true);
    setFields((currentFields) => currentFields.map((field, fieldIndex) => (fieldIndex === index ? value : field)));
  }

  return (
    <Panel title="Cron generator">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Build a crontab line from common presets or edit the five cron fields directly. Cron field order is minute, hour,
        day of month, month, day of week.
      </p>
      <div className="mt-5 grid gap-6 lg:grid-cols-[minmax(0,1fr)_260px]">
        <div>
          <div className="mb-4 flex flex-wrap gap-2">
            <button
              className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
                !useCustomSchedule
                  ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
                  : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
              }`}
              type="button"
              onClick={() => {
                setUseCustomSchedule(false);
                selectPreset(preset);
              }}
            >
              Preset schedule
            </button>
            <button
              className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
                useCustomSchedule
                  ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
                  : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
              }`}
              type="button"
              onClick={() => setUseCustomSchedule(true)}
            >
              Custom schedule
            </button>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {!useCustomSchedule && (
              <Field>
                <Label>Schedule preset</Label>
                <FieldSelect className={inputClass()} value={preset} onChange={(event) => selectPreset(event.target.value)}>
                  {cronPresets.map((cronPreset) => (
                    <option key={cronPreset.value} value={cronPreset.value}>
                      {cronPreset.label}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
            )}
            <Field>
              <Label>Command</Label>
              <FieldInput
                className={inputClass(false, command === commandExample)}
                value={command}
                onChange={(event) => setCommand(event.target.value)}
                onFocus={() => clearExampleValue(command, commandExample, setCommand)}
                onBlur={() => restoreExampleValue(command, commandExample, setCommand)}
              />
            </Field>
          </div>
          {useCustomSchedule && (
            <div className="mt-5 grid gap-4 sm:grid-cols-5">
              {fields.map((field, index) => (
                <Field key={cronFieldLabels[index]} error={fieldErrors[index]}>
                  <Label>{cronFieldLabels[index]}</Label>
                  <FieldInput
                    className={inputClass(Boolean(fieldErrors[index]))}
                    value={field}
                    onChange={(event) => updateField(index, event.target.value)}
                  />
                  <FieldError />
                </Field>
              ))}
            </div>
          )}
          {hasErrors ? (
            <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
              Fix the cron field values before using the generated crontab line.
            </div>
          ) : (
            <CommandBlock>{crontabLine}</CommandBlock>
          )}
        </div>
        <aside className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <h3 className="text-sm font-semibold text-zinc-200">Cron symbols</h3>
          <div className="mt-3 space-y-2 text-sm text-zinc-400">
            <p><span className="font-mono text-zinc-300">*</span> every value</p>
            <p><span className="font-mono text-zinc-300">*/5</span> every 5 units</p>
            <p><span className="font-mono text-zinc-300">1,15</span> list of values</p>
            <p><span className="font-mono text-zinc-300">1-5</span> range</p>
          </div>
        </aside>
      </div>
    </Panel>
  );
}
