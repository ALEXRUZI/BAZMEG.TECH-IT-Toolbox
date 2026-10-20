import { useState } from 'react';

import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, inputClass, FieldSelect, FieldTextarea, FieldError } from '../../components/Panel';
import { clearExampleValue, restoreExampleValue } from '../../components/inputExamples';

type EncoderMode = 'base64-encode' | 'base64-decode' | 'url-encode' | 'url-decode';

export function EncoderTool() {
  const encoderSamples: Record<EncoderMode, string> = {
    'base64-encode': 'Hello from IT Toolbox!',
    'base64-decode': 'SGVsbG8gZnJvbSBJVCBUb29sYm94IQ==',
    'url-encode': 'Hello from IT Toolbox!',
    'url-decode': 'Hello%20from%20IT%20Toolbox%21',
  };
  const [mode, setMode] = useState<EncoderMode>('base64-encode');
  const [input, setInput] = useState(encoderSamples['base64-encode']);
  const sample = encoderSamples[mode];
  let output = '';
  let error = '';

  try {
    if (mode === 'base64-encode') {
      output = btoa(unescape(encodeURIComponent(input)));
    } else if (mode === 'base64-decode') {
      output = decodeURIComponent(escape(atob(input.trim())));
    } else if (mode === 'url-encode') {
      output = encodeURIComponent(input);
    } else {
      output = decodeURIComponent(input);
    }
  } catch {
    error = mode === 'base64-decode' ? 'Input is not valid Base64.' : 'Input is not valid URL-encoded text.';
  }

  return (
    <Panel title="Base64 / URL encode">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Encode or decode Base64 and URL-escaped text locally in the browser, useful for tokens, query strings, and quick
        troubleshooting.
      </p>
      <div className="mt-5 grid gap-4 sm:grid-cols-[220px_1fr]">
        <Field>
          <Label>Mode</Label>
          <FieldSelect
            className={inputClass()}
            value={mode}
            onChange={(event) => {
              const nextMode = event.target.value as EncoderMode;
              setMode(nextMode);
              setInput(encoderSamples[nextMode]);
            }}
          >
            <option value="base64-encode">Base64 encode</option>
            <option value="base64-decode">Base64 decode</option>
            <option value="url-encode">URL encode</option>
            <option value="url-decode">URL decode</option>
          </FieldSelect>
        </Field>
        <Field error={error}>
          <Label>Input</Label>
          <FieldTextarea
            className={`${inputClass(Boolean(error), input === sample)} min-h-32 font-mono`}
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onFocus={() => clearExampleValue(input, sample, setInput)}
            onBlur={() => restoreExampleValue(input, sample, setInput)}
          />
          <FieldError />
        </Field>
      </div>
      {error ? (
        <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-4 text-sm text-red-100">
          Fix the input before using the output.
        </div>
      ) : (
        <CommandBlock>{output}</CommandBlock>
      )}
    </Panel>
  );
}
