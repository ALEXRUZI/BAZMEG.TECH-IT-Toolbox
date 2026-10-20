import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Panel, inputClass } from '../../components/Panel';
import { clearExampleValue, restoreExampleValue } from '../../components/inputExamples';
import { formatJsonLossless, formatYamlLite } from './jsonYamlHelpers';

export function JsonYamlFormatter() {
  const jsonSample = '{"name":"it-toolbox","enabled":true,"tools":["json","yaml"]}';
  const yamlSample = 'name: it-toolbox\nenabled: true\ntools:\n  - json\n  - yaml';
  const [mode, setMode] = useState<'json' | 'yaml'>('json');
  const [input, setInput] = useState(jsonSample);
  const [indentSize, setIndentSize] = useState('2');
  const activeSample = mode === 'json' ? jsonSample : yamlSample;
  let formatted = '';
  let error = '';

  if (mode === 'json') {
    const jsonResult = formatJsonLossless(input, indentSize === '4' ? 4 : 2);
    formatted = jsonResult.output;
    error = jsonResult.error;
  } else {
    const yamlResult = formatYamlLite(input);
    formatted = yamlResult.output;
    error = yamlResult.error;
  }

  function changeMode(nextMode: 'json' | 'yaml') {
    setMode(nextMode);
    setInput(nextMode === 'json' ? jsonSample : yamlSample);
  }

  return (
    <Panel title="JSON/YAML formatter">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Format JSON losslessly, preserving exact numbers, string escapes, key order and duplicate keys.
        YAML cleanup is lightweight and conservative, not full syntax validation: only simple mappings/sequences
        and single-line scalars are supported; uncertain constructs are refused. Processing stays in your browser.
        Limits: 1,000,000 input characters, 128 JSON nesting levels and 4,000,000 output characters.
      </p>
      <div className="mt-5 flex flex-wrap gap-2">
        <button
          className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
            mode === 'json'
              ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
              : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => changeMode('json')}
        >
          JSON
        </button>
        <button
          className={`rounded-lg border px-3 py-2 text-sm font-semibold transition ${
            mode === 'yaml'
              ? 'border-emerald-400/50 bg-emerald-500/10 text-emerald-300'
              : 'border-white/10 text-zinc-300 hover:border-emerald-400/40'
          }`}
          type="button"
          onClick={() => changeMode('yaml')}
        >
          YAML
        </button>
      </div>
      <div className="mt-5 grid gap-4 sm:grid-cols-[1fr_160px]">
        <Field>
          <label className="text-sm font-medium text-zinc-300" htmlFor="json-yaml-input">Input</label>
          <textarea
            className={`${inputClass(Boolean(error), input === activeSample)} min-h-44 font-mono`}
            id="json-yaml-input"
            aria-invalid={Boolean(error)}
            aria-describedby={error ? 'json-yaml-error' : undefined}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onFocus={() => clearExampleValue(input, activeSample, setInput)}
            onBlur={() => restoreExampleValue(input, activeSample, setInput)}
          />
          {error && <p id="json-yaml-error" role="alert" className="text-xs leading-5 text-red-300">{error}</p>}
        </Field>
        {mode === 'json' && (
          <Field>
            <label className="text-sm font-medium text-zinc-300" htmlFor="json-yaml-indent">Indent</label>
            <select id="json-yaml-indent" className={inputClass()} value={indentSize} onChange={(event) => setIndentSize(event.target.value)}>
              <option value="2">2 spaces</option>
              <option value="4">4 spaces</option>
            </select>
          </Field>
        )}
      </div>
      {error ? (
        <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
          Fix the {mode.toUpperCase()} input before using the formatted output.
        </div>
      ) : (
        <CommandBlock>{formatted}</CommandBlock>
      )}
    </Panel>
  );
}
