import { useEffect, useRef, useState } from 'react';
import { zipSync, strToU8, type Zippable } from 'fflate';
import { CopyButton } from '../../components/CopyButton';
import { ResultItem } from '../../components/Panel';
import { algorithms, formatExplanation } from './sshAlgorithms';
import type { KeyOutput, Result } from './sshTypes';

function Output({ output, download }: { output: KeyOutput; download: (bytes: Uint8Array, filename: string) => void }) {
  const [revealed, setRevealed] = useState(false), [copyAllowed, setCopyAllowed] = useState(false), [feedback, setFeedback] = useState('');
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  async function copy() {
    try { await navigator.clipboard.writeText(output.text); if (mounted.current) { setFeedback('Copied'); setCopyAllowed(false); } }
    catch { if (mounted.current) setFeedback('Clipboard unavailable; use Download.'); }
  }
  return <section aria-label={output.label} className="min-w-0 space-y-3 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
    <h3 className="text-sm font-semibold">{output.label}</h3>
    <p className="break-all font-mono text-xs text-zinc-400">{output.filename}</p>
    {output.bytes && <p className="text-sm text-amber-300">Sensitive binary private key ({output.bytes.length} bytes). Download only; no text reveal or clipboard copy. SSH-1 protection is obsolete and unauthenticated.</p>}
    {output.private && !output.bytes && <>
      <CopyButton aria-expanded={revealed} onClick={() => setRevealed(!revealed)}>{revealed ? 'Hide private key' : 'Reveal private key'}</CopyButton>
      <p className="text-xs text-amber-300">Private keys are sensitive even when encrypted. Clipboard contents may be read by other applications.</p>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={copyAllowed} onChange={e => setCopyAllowed(e.target.checked)} />I understand the clipboard risk for this private key.</label>
    </>}
    {!output.bytes && (!output.private || revealed) && <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 [overflow-wrap:anywhere]">{output.text}</pre>}
    <div className="flex flex-wrap items-center gap-3">{!output.bytes && <CopyButton disabled={output.private && !copyAllowed} onClick={() => void copy()}>Copy text</CopyButton>}<CopyButton onClick={() => download(output.bytes ?? strToU8(output.text), output.filename)}>Download</CopyButton><span role="status" className="text-xs text-zinc-400">{feedback}</span></div>
  </section>;
}
export function SshResults({ result }: { result: Result }) {
  const [selected, setSelected] = useState(result.outputs.map(output => output.filename)), [error, setError] = useState('');
  const urls = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  useEffect(() => { const current = urls.current; return () => { for (const [url, timer] of current) { clearTimeout(timer); URL.revokeObjectURL(url); } current.clear(); }; }, []);
  function download(bytes: Uint8Array, filename: string) {
    try {
      const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: filename.endsWith('.zip') ? 'application/zip' : filename.endsWith('.ssh1') ? 'application/octet-stream' : 'text/plain;charset=utf-8' }));
      urls.current.set(url, setTimeout(() => { URL.revokeObjectURL(url); urls.current.delete(url); }, 1000));
      const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    } catch { setError('Download could not be created.'); }
  }
  const info = result.inspector;
  return <div className="space-y-4">
    <h3 className="text-lg font-semibold">Key Inspector</h3>
    {info.classification === 'Legacy / Insecure' && <p role="alert" className="text-red-300">Legacy / Insecure — unsuitable for production use.</p>}
    {formatExplanation(algorithms.find(a => a.label === info.algorithm)?.id ?? '') && <p className="text-sm text-amber-300">{formatExplanation(algorithms.find(a => a.label === info.algorithm)!.id)}</p>}
    <div className="grid gap-3 sm:grid-cols-2">
      <ResultItem label="Algorithm / parameters" value={`${info.algorithm}; ${info.parameters}`} />
      <ResultItem label="SSH identifier / classification" value={`${info.identifier}; ${info.classification}`} />
      <ResultItem label="Detected format / input encryption" value={`${info.format}; ${info.encrypted ? info.identifier === 'SSH-1 RSA' ? 'obsolete protection' : 'protected' : 'unencrypted'}`} />
      <ResultItem label="Comment" value={info.comment} />
      <ResultItem label={info.identifier === 'SSH-1 RSA' ? 'Historical MD5 fingerprint (identification only)' : 'SHA-256 fingerprint'} value={info.fingerprint} />
      <ResultItem label="Compatible exports" value={info.exports} />
    </div>
    {result.outputs.map(output => <Output key={output.filename} output={output} download={download} />)}
    <fieldset className="space-y-2 rounded-2xl border border-white/10 p-4"><legend className="px-2 text-sm font-semibold">ZIP contents</legend>
      <p className="text-xs text-amber-300">The ZIP archive itself is NOT encrypted. It contains only selected outputs below, protected only as indicated on each key file.</p>
      {result.outputs.map(output => <label key={output.filename} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={selected.includes(output.filename)} onChange={e => setSelected(e.target.checked ? [...selected, output.filename] : selected.filter(name => name !== output.filename))} />Include {output.label}</label>)}
      <CopyButton disabled={!selected.length} onClick={() => {
        const files: Zippable = {};
        for (const output of result.outputs) if (selected.includes(output.filename)) files[output.filename] = [output.bytes ?? strToU8(output.text), { level: 0, os: 3, attrs: 0o100600 << 16 }];
        download(zipSync(files), 'ssh-key-outputs.zip');
      }}>Download all as ZIP</CopyButton>
    </fieldset>
    {error && <p role="alert" className="text-red-300">{error}</p>}
  </div>;
}
