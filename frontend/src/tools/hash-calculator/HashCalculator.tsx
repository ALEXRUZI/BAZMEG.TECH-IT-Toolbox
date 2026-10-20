import { useRef, useState } from 'react';
import { Field, FieldDescription, FieldError, FieldInput, FieldSelect, FieldTextarea, Label, Panel, inputClass } from '../../components/Panel';
import { algorithms, type Algorithm } from './types';
import { verifyChecksum } from './checksum';
import { useExactTextEditor } from './useExactTextEditor';
import { DigestResult } from './DigestResult';
import { useHashWorker } from './useHashWorker';
import { LegacyWarning, legacyAlgorithms, type LegacyAlgorithm } from './LegacyWarning';

const buttonClass = 'rounded-xl border border-emerald-500/30 px-4 py-2 text-sm font-semibold text-emerald-300 hover:bg-emerald-500/10 focus-visible:outline-2 focus-visible:outline-emerald-400 disabled:opacity-40';

export function HashCalculator() {
  const [mode, setMode] = useState<'file' | 'text'>('file');
  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<Algorithm[]>(['sha256']);
  const [acknowledged, setAcknowledged] = useState<LegacyAlgorithm[]>([]);
  const pending = legacyAlgorithms.filter((id) => selected.includes(id) && !acknowledged.includes(id));
  const algorithmControls = useRef<HTMLFieldSetElement | null>(null);
  const [expected, setExpected] = useState('');
  const [verificationAlgorithm, setVerificationAlgorithm] = useState<Algorithm | 'auto'>('auto');
  const [inputError, setInputError] = useState('');
  const picker = useRef<HTMLInputElement | null>(null);
  const hashing = useHashWorker();
  const editor = useExactTextEditor(hashing.reset);
  const verification = verifyChecksum(expected, verificationAlgorithm, hashing.digests);
  const { processed, total, elapsedMs } = hashing.progress;
  const percent = total ? Math.floor(processed / total * 100) : hashing.status === 'done' ? 100 : 0;

  function chooseFiles(files: File[]) {
    hashing.reset();
    setInputError('');
    if (files.length !== 1) { setFile(null); setInputError('Choose exactly one file. Batch and directory hashing are not supported.'); return; }
    setFile(files[0]);
  }
  function reset() {
    hashing.reset(); setFile(null); editor.reset(); setExpected(''); setInputError(''); setSelected(['sha256']); setAcknowledged([]); setVerificationAlgorithm('auto');
    if (picker.current) picker.current.value = '';
  }

  return <Panel title="Hash Calculator">
    <p className="text-sm leading-6 text-zinc-300">Files are processed locally in your browser. File contents are never uploaded or sent to the server. Text stays local too; nothing is saved.</p>
    <div className="mt-5 space-y-5">
      <Field>
        <Label>Input mode</Label>
        <FieldSelect className={inputClass()} value={mode} onChange={(event) => { hashing.reset(); setInputError(''); setMode(event.target.value as 'file' | 'text'); }}>
          <option value="file">File</option><option value="text">UTF-8 text</option>
        </FieldSelect>
      </Field>
      {mode === 'file' ? <div onDragOver={(event) => event.preventDefault()} onDrop={(event) => {
        event.preventDefault();
        const items = Array.from(event.dataTransfer.items);
        if (items.some((item) => item.webkitGetAsEntry?.()?.isDirectory)) { hashing.reset(); setFile(null); setInputError('Directories are not supported. Choose one regular file.'); return; }
        chooseFiles(Array.from(event.dataTransfer.files));
      }} className="rounded-2xl border border-dashed border-emerald-500/30 bg-zinc-950/60 p-5">
        <Field error={inputError} description="Drop one file here or use the file picker. Empty files are supported.">
          <Label>Choose file</Label>
          <FieldInput ref={picker} type="file" className={`${inputClass()} focus-visible:outline-2 focus-visible:outline-emerald-400`} onChange={(event) => {
            if (event.target.files?.length) chooseFiles(Array.from(event.target.files));
            event.target.value = ''; // Selecting the same file again must trigger replacement.
          }} />
          <FieldDescription /><FieldError />
        </Field>
        {file && <p className="mt-3 break-all text-sm text-zinc-300">{file.name} · {file.size.toLocaleString()} bytes</p>}
      </div> : <Field error={editor.error} description="UTF-8 text: unchanged line endings and pasted LF/CRLF/CR are preserved; no Unicode normalization. Typed newlines are LF. Undo/redo retains the last 50 edits while this tool is open. Edits without a reliable range are rejected rather than guessed. Lone surrogates encode as U+FFFD. Empty text is supported.">
        <Label>Text to hash</Label>
        <FieldTextarea {...editor.props} className={`${inputClass(Boolean(editor.error))} min-h-36 font-mono`} spellCheck={false} autoComplete="off" />
        <FieldDescription /><FieldError />
      </Field>}
      <fieldset ref={algorithmControls} tabIndex={-1} className="space-y-3 focus-visible:outline-2 focus-visible:outline-emerald-400">
        <legend className="mb-2 text-sm font-medium text-zinc-300">Algorithms</legend>
        <div className="grid gap-3 sm:grid-cols-3">
          {algorithms.map((algorithm) => <Field key={algorithm.id}>
            <div className="flex items-center gap-2">
              <FieldInput type="checkbox" className="size-4 accent-emerald-500 focus-visible:outline-2 focus-visible:outline-emerald-400" checked={selected.includes(algorithm.id)} onChange={(event) => {
                hashing.reset(); setSelected(event.target.checked ? [...selected, algorithm.id] : selected.filter((id) => id !== algorithm.id));
                if (!event.target.checked) setAcknowledged((previous) => previous.filter((id) => id !== algorithm.id));
              }} />
              <Label>{algorithm.label}</Label>
            </div>
          </Field>)}
        </div>
        <p className="text-xs text-zinc-400">BLAKE3 and unkeyed BLAKE2b-256 use 256-bit digests. CRC32 (IEEE) and xxHash32 (seed 0) are non-cryptographic: they detect accidental corruption, not malicious modification. More algorithms increase CPU work, but the file is read only once.</p>
        <p className="text-xs leading-5 text-amber-300">MD5 and SHA-1 are cryptographically broken (collision attacks). Use only for legacy compatibility and non-adversarial integrity checks, not security-sensitive verification. Prefer SHA-256 or stronger.</p>
      </fieldset>
      {pending.length > 0 && <>
        <LegacyWarning selectedLegacy={legacyAlgorithms.filter((id) => selected.includes(id))} buttonClass={buttonClass} onSwitch={() => {
          hashing.reset();
          setSelected((previous) => [...new Set<Algorithm>([...previous.filter((id) => id !== 'md5' && id !== 'sha1'), 'sha256'])]);
          setAcknowledged([]);
          // Focus a stable control, not an action about to disappear.
          algorithmControls.current?.focus();
        }} onAcknowledge={() => {
          setAcknowledged((previous) => [...new Set([...previous, ...pending])]);
          algorithmControls.current?.focus();
        }} />
        <p id="hash-legacy-gate" role="status" className="text-sm text-red-300">Calculation is disabled until you acknowledge the selected legacy algorithms' security risks or switch to SHA-256.</p>
      </>}
      <div className="flex flex-wrap gap-3">
        <button type="button" className={buttonClass} aria-describedby={pending.length ? 'hash-legacy-gate' : undefined} disabled={pending.length > 0 || !selected.length || (mode === 'file' && !file) || (mode === 'text' && editor.composing)} onClick={() => hashing.start({ input: mode === 'file' ? file! : editor.text, algorithms: selected })}>{hashing.status === 'running' ? 'Restart calculation' : 'Calculate hashes'}</button>
        {hashing.status === 'running' && <button type="button" className={buttonClass} onClick={hashing.cancel}>Cancel</button>}
        <button type="button" className={buttonClass} onClick={reset}>Reset</button>
      </div>
      {!selected.length && <p role="alert" className="text-sm text-red-300">Select at least one algorithm.</p>}
      <p role="status" className={`text-sm ${hashing.error ? 'text-red-300' : 'text-zinc-300'}`}>
        {hashing.status === 'running' ? `Hashing ${percent}%` : hashing.status === 'done' ? 'Hashing complete.' : hashing.status === 'cancelled' ? 'Hashing cancelled. The input is available to restart.' : hashing.error}
      </p>
      {(hashing.status === 'running' || hashing.status === 'done') && <div className="space-y-2">
        <progress aria-label="Hashing progress" max={100} value={percent} className="h-3 w-full accent-emerald-500" />
        <p className="text-xs text-zinc-400">{processed.toLocaleString()} / {total.toLocaleString()} bytes · {(elapsedMs / 1000).toFixed(1)} s{elapsedMs >= 1000 ? ` · ${(processed / 1048576 / (elapsedMs / 1000)).toFixed(1)} MiB/s average` : ''}</p>
      </div>}
      <div className="grid min-w-0 gap-3 lg:grid-cols-2">
        {algorithms.map(({ id, label }) => hashing.digests[id] && <DigestResult key={id} label={label} digest={hashing.digests[id]} />)}
      </div>
      <div className="grid gap-4 sm:grid-cols-[1fr_220px]">
        <Field error={verification.error}>
          <Label>Expected checksum</Label>
          <FieldInput className={inputClass(Boolean(verification.error))} value={expected} onChange={(event) => setExpected(event.target.value)} spellCheck={false} autoComplete="off" />
          <FieldError />
        </Field>
        <Field>
          <Label>Checksum algorithm</Label>
          <FieldSelect className={inputClass()} value={verificationAlgorithm} onChange={(event) => setVerificationAlgorithm(event.target.value as Algorithm | 'auto')}>
            <option value="auto">Infer from length</option>
            {algorithms.map(({ id, label }) => <option key={id} value={id}>{label}</option>)}
          </FieldSelect>
        </Field>
      </div>
      {verification.message && <p role="status" className={`rounded-xl border p-3 text-sm ${verification.matches ? 'border-emerald-400/30 text-emerald-300' : verification.mismatch ? 'border-red-400/40 bg-red-400/10 text-red-300' : 'border-amber-400/30 text-amber-300'}`}>{verification.message}</p>}
      <p className="text-xs leading-5 text-zinc-400">A matching checksum does not establish source authenticity. Obtain the expected checksum through a trusted channel. This is not password hashing.</p>
    </div>
  </Panel>;
}
