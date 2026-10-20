import { useEffect, useRef, useState } from 'react';
import { Field, FieldInput, FieldSelect, FieldTextarea, Label, Panel, inputClass } from '../../components/Panel';
import { CopyButton } from '../../components/CopyButton';
import { algorithms, capability, compatibleSelection, exportDescription, families, formatExplanation, legacyAcknowledgment, operationCompatibility, publicLabel, supportedFormats, unsupportedFormatExplanation, type Family } from './sshAlgorithms';
import { MAX_IMPORT } from './sshBytes';
import { detectFormat, inputAlgorithmHint, validateOptions } from './sshValidation';
import { SshProtection } from './SshProtection';
import { SshResults } from './SshResults';
import { SshOutputOption } from './SshOutputOption';
import { useSshWorker } from './useSshWorker';
import type { ExportOptions, OutputFormat } from './sshTypes';

const tabs = ['Generate key pair', 'Extract public key', 'Convert key formats'] as const;
const defaults = (): ExportOptions => ({ protected: true, passphrase: '', confirmation: '', unencryptedAcknowledged: false, formats: ['public', 'openssh', 'ppk'] });
export function SshKeyGenerator() {
  const [tab, setTab] = useState(0), [family, setFamily] = useState<Family>('EdDSA'), [id, setId] = useState('ed25519');
  const [comment, setComment] = useState(''), [overrideComment, setOverrideComment] = useState(false), [legacy, setLegacy] = useState(false);
  const [options, setOptions] = useState(defaults), [source, setSource] = useState(''), [importPassphrase, setImportPassphrase] = useState('');
  const [sourceBytes, setSourceBytes] = useState<Uint8Array>();
  const fileInput = useRef<HTMLInputElement>(null), fileEpoch = useRef(0);
  const worker = useSshWorker(), a = algorithms.find(item => item.id === id)!;
  const knownOutputProfile = tab === 0 ? id : inputAlgorithmHint(source, sourceBytes);
  const outputProfile = knownOutputProfile ?? 'ed25519';
  const available = supportedFormats(outputProfile);
  const filtered = compatibleSelection(outputProfile, options.formats);
  // Only normalize an incompatible selection, not a deliberate empty selection.
  const outputOptions = { ...options, formats: filtered };
  useEffect(() => {
    setOptions(current => {
      return { ...current, unencryptedAcknowledged: false, historicalEncryptionAcknowledged: false, formats: compatibleSelection(outputProfile, current.formats) };
    });
  }, [outputProfile]); // Preserve protection, reset security acknowledgments on profile changes.
  const capable = a.supported && (worker.capabilities?.includes(capability(a.id)) ?? false);
  useEffect(() => () => { fileEpoch.current++; }, []);
  useEffect(() => {
    if (worker.result) { setSource(''); setSourceBytes(undefined); setImportPassphrase(''); setOptions(current => ({ ...current, passphrase: '', confirmation: '' })); if (fileInput.current) fileInput.current.value = ''; }
  }, [worker.result]);
  // Settings edits invalidate crypto results, not the selected file's pending
  // read. Only source replacement/discard makes that asynchronous read stale.
  function invalidate() { worker.clear(); }
  function reset() { fileEpoch.current++; invalidate(); setSource(''); setSourceBytes(undefined); setImportPassphrase(''); setOptions(defaults()); setComment(''); setOverrideComment(false); setLegacy(false); setFamily('EdDSA'); setId('ed25519'); if (fileInput.current) fileInput.current.value = ''; }
  function changeOptions(value: ExportOptions) { invalidate(); setOptions(value); }
  let detected = '', invalid = '';
  if (source || sourceBytes) { try { detected = detectFormat(source, sourceBytes); } catch (error) { invalid = error instanceof Error ? error.message : 'Unsupported input.'; } }
  if (tab !== 1) { try { validateOptions(outputOptions); } catch (error) { invalid ||= error instanceof Error ? error.message : 'Invalid output settings.'; } }
  const disabled = worker.busy || worker.capabilities === null || !worker.capabilities.length || (tab === 0 ? !a.supported || !capable || Boolean(a.legacy && !legacy) : !source && !sourceBytes) || Boolean(invalid);
  function run() {
    if (disabled) return;
    fileEpoch.current++;
    worker.run(tab === 0 ? { operation: 'generate', algorithm: id, comment, legacyAcknowledged: legacy, options: outputOptions } : { operation: tab === 1 ? 'extract' : 'convert', text: source, bytes: sourceBytes, passphrase: importPassphrase, comment: overrideComment ? comment : undefined, options: outputOptions });
  }
  return <Panel title="SSH Key Generator & Converter"><div className="space-y-5">
    <p className="text-sm text-zinc-400">Keys and passphrases stay in this browser. No upload, storage or remote crypto. A compromised bundle, browser extension or device can still steal secrets; browser memory cannot be guaranteed erased. Use a trusted, secure origin.</p>
    <div role="tablist" aria-label="SSH key operation" className="flex flex-wrap gap-2">{tabs.map((name, index) => <CopyButton key={name} id={`ssh-tab-${index}`} role="tab" aria-selected={tab === index} aria-controls="ssh-operation" tabIndex={tab === index ? 0 : -1} disabled={worker.busy} onClick={() => { reset(); setTab(index); }} onKeyDown={e => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
      e.preventDefault(); const next = e.key === 'Home' ? 0 : e.key === 'End' ? 2 : (tab + (e.key === 'ArrowRight' ? 1 : 2)) % 3;
      reset(); setTab(next); document.getElementById(`ssh-tab-${next}`)?.focus();
    }}>{name}</CopyButton>)}</div>
    <div id="ssh-operation" role="tabpanel" aria-labelledby={`ssh-tab-${tab}`} className="space-y-4">
      {tab === 0 ? <>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field><Label>Algorithm family</Label><FieldSelect disabled={worker.busy} className={inputClass()} value={family} onChange={e => { invalidate(); const f = e.target.value as Family; setFamily(f); setId(algorithms.find(item => item.family === f)!.id); setLegacy(false); }}>{families.map(f => <option key={f}>{f}</option>)}</FieldSelect></Field>
          <Field><Label>Algorithm / curve / key size</Label><FieldSelect disabled={worker.busy} className={inputClass()} value={id} onChange={e => { invalidate(); setId(e.target.value); setLegacy(false); }}>{algorithms.filter(item => item.family === family).map(item => <option key={item.id} value={item.id}>{item.label} — {item.classification}{item.supported ? '' : ' (Unavailable)'}</option>)}</FieldSelect></Field>
        </div>
        <div className="space-y-2 rounded-2xl border border-white/10 bg-zinc-950/60 p-4 text-sm"><p>{a.classification}; {a.strength}; <code>{a.identifier}</code></p><p className="text-zinc-400">{a.note}</p><p>{a.supported ? `Available: ${exportDescription(id)}; private keys encrypted or unencrypted.` : 'Generation, extraction and conversion of this selection are unavailable.'}</p>{a.supported && <p className="text-xs text-zinc-400">{operationCompatibility(id).generation}. Fingerprint: {operationCompatibility(id).fingerprint}.</p>}</div>
        {a.legacy && <div className="space-y-2 text-sm text-red-300"><p role="alert">{a.label}: Legacy / Insecure — unsuitable for production use.</p><label className="flex items-center gap-2"><input disabled={worker.busy} type="checkbox" checked={legacy} onChange={e => { invalidate(); setLegacy(e.target.checked); }} />{legacyAcknowledgment}</label></div>}
      </> : <>
        <p className="text-sm text-zinc-400">Import encrypted or unencrypted OpenSSH (AES-256-CTR/CBC, bcrypt), PPK v3 (AES-256-CBC, Argon2), or SSH-1 binary files via local file input. Ed448 requires PPK v3. Bounded to 64 KiB. PKCS#8/PEM, PPK v2, certificates, hardware keys and ssh.com are unavailable.</p>
        <Field><Label>Local private-key file</Label><FieldInput ref={fileInput} type="file" disabled={worker.busy} className={inputClass()} onChange={async e => {
          fileEpoch.current++; invalidate(); setSource(''); setSourceBytes(undefined); const epoch = fileEpoch.current, file = e.target.files?.[0]; if (!file) return;
          if (file.size > MAX_IMPORT) { worker.setError('Import exceeds the 64 KiB limit.'); e.target.value = ''; return; }
          try { const bytes = new Uint8Array(await file.arrayBuffer()); if (fileEpoch.current !== epoch) return; if (inputAlgorithmHint('', bytes) === 'rsa1') setSourceBytes(bytes); else setSource(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
          catch { if (fileEpoch.current === epoch) worker.setError('File is neither supported SSH-1 binary nor valid UTF-8 key text.'); }
        }} /></Field>
        <Field><Label>Paste private-key text</Label><FieldTextarea disabled={worker.busy} className={`${inputClass()} font-mono`} rows={5} maxLength={MAX_IMPORT + 1} autoComplete="off" spellCheck={false} value={source} onChange={e => { fileEpoch.current++; invalidate(); setSourceBytes(undefined); setSource(e.target.value); }} /></Field>
        {sourceBytes && <p className="text-sm text-amber-300">Binary SSH-1 file loaded ({sourceBytes.length} bytes); private bytes are not displayed as text.</p>}
        <p className="text-xs text-zinc-400">Detected content: {detected || 'No supported format detected'}. Filenames/extensions are not trusted.</p>
        <Field><Label>Import passphrase</Label><FieldInput disabled={worker.busy} className={inputClass()} type="password" autoComplete="off" maxLength={1024} value={importPassphrase} onChange={e => { invalidate(); setImportPassphrase(e.target.value); }} /></Field>
        <label className="flex items-center gap-2 text-sm"><input disabled={worker.busy} type="checkbox" checked={overrideComment} onChange={e => { invalidate(); setOverrideComment(e.target.checked); }} />Replace imported comment (otherwise preserve it)</label>
      </>}
      {(tab === 0 || overrideComment) && <Field><Label>Key comment</Label><FieldInput disabled={worker.busy} className={inputClass()} maxLength={256} value={comment} onChange={e => { invalidate(); setComment(e.target.value); }} /></Field>}
      {tab !== 1 && <>
        <fieldset disabled={worker.busy} className="flex flex-wrap gap-3 rounded-2xl border border-white/10 p-4"><legend className="px-2 text-sm font-semibold">Selected outputs</legend>{(['public', 'openssh', 'ppk', 'ssh1'] as OutputFormat[]).map(format => <SshOutputOption key={`${knownOutputProfile ?? 'unknown'}-${format}`} label={format === 'public' ? publicLabel(outputProfile) : format === 'openssh' ? 'OpenSSH private' : format === 'ssh1' ? 'SSH-1 binary private' : 'PPK v3 private'} explanation={unsupportedFormatExplanation(knownOutputProfile, format)} disabled={!available.includes(format)} checked={outputOptions.formats.includes(format)} onChange={checked => changeOptions({ ...outputOptions, formats: checked ? [...outputOptions.formats, format] : outputOptions.formats.filter(item => item !== format) })} />)}</fieldset>
        {formatExplanation(outputProfile) && <p id="ssh-format-unavailable" className="text-sm text-amber-300">{formatExplanation(outputProfile)}</p>}
        {outputOptions.formats.some(format => format !== 'public') && <SshProtection options={outputOptions} change={changeOptions} disabled={worker.busy} />}
      </>}
      <p className="text-xs text-zinc-400">Optional RFC 4716, PKCS#8 and PPK v1/v2 exports are not implemented. No FIPS validation is claimed. RSA key encoding is not a promise to negotiate deprecated RSA-SHA1 signatures.</p>
      {worker.capabilities === null ? <p role="status">Checking local browser cryptographic capabilities…</p> : !worker.capabilities.length ? <p role="alert" className="text-red-300">This browser/origin cannot run the required secure Web Crypto worker.</p> : tab === 0 && a.supported && !capable ? <p role="alert" className="text-red-300">This browser cannot generate {a.label} with the required local cryptographic implementation; generation is disabled, without a weaker fallback.</p> : null}
      {tab === 0 && a.supported && a.bits && capable && <p className="text-xs text-zinc-400">Native support for {a.label} is checked only when you generate. If this size is unavailable, the operation fails without trying another size or algorithm.</p>}
      {invalid && <p role="status" className="text-amber-300">{invalid}</p>}
      {worker.error && <p role="alert" className="text-red-300">{worker.error}</p>}
      <div className="flex flex-wrap items-center gap-3"><CopyButton disabled={disabled} onClick={run}>{tabs[tab]}</CopyButton><CopyButton onClick={reset}>{worker.busy ? 'Cancel and reset' : 'Reset / discard keys'}</CopyButton><span role="status" className="text-sm text-zinc-400">{worker.busy ? 'Processing locally in a worker…' : ''}</span></div>
    </div>
    {worker.result && <SshResults result={worker.result} />}
  </div></Panel>;
}
