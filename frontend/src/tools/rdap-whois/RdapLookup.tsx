import { useEffect, useRef, useState } from 'react';
import { Field, Label, FieldInput, FieldSelect, FieldError, FieldDescription, Panel, inputClass } from '../../components/Panel';
import { CopyButton } from '../../components/CopyButton';
import { useTextClipboard } from '../../components/useTextClipboard';
import { CommandBlock } from '../../components/CommandBlock';
import { ResultImageCapture, ResultImageCopyControls, useResultImageClipboard } from '../../components/ResultImageExport';
import { fetchRegistration } from './rdapApi';
import { classifyRegistration, downloadRegistration, normalizedExport } from './rdapHelpers';
import { RegistrationDiagnostics, RegistrationOverview } from './RdapResults';
import type { RegistrationMode, RegistrationResponse } from './rdapTypes';

export function RdapLookup() {
  const [target, setTarget] = useState(''), [mode, setMode] = useState<RegistrationMode>('auto');
  const [response, setResponse] = useState<RegistrationResponse | null>(null), [error, setError] = useState('');
  const [loading, setLoading] = useState(false), [calculatedAt, setCalculatedAt] = useState(Date.now());
  const owner = useRef<AbortController | null>(null);
  const image = useResultImageClipboard('Copied registration result image.');
  useEffect(() => () => { owner.current?.abort(); owner.current = null; }, []);
  let validation = '', classification = '';
  if (target) { try { const input = classifyRegistration(target); classification = `${input.kind}: ${input.canonical}`; } catch (e) { validation = e instanceof Error ? e.message : 'Invalid identifier.'; } }
  function cancel() { owner.current?.abort(); owner.current = null; setLoading(false); setError('Registration lookup was cancelled.'); }
  async function run() {
    try { classifyRegistration(target); } catch { return; }
    owner.current?.abort();
    const controller = new AbortController(); owner.current = controller;
    setLoading(true); setResponse(null); setError(''); image.clearCopyImageStatus();
    try {
      const result = await fetchRegistration(target, mode, controller.signal);
      if (owner.current !== controller) return;
      setResponse(result); setCalculatedAt(Date.now());
    } catch (e) {
      if (owner.current === controller) setError(e instanceof Error ? e.message : 'Registration lookup failed.');
    } finally { if (owner.current === controller) { owner.current = null; setLoading(false); } }
  }
  const result = response?.ok ? response : null;
  const structured = useTextClipboard(result ? JSON.stringify(normalizedExport(result), null, 2) : '');
  return <Panel title="RDAP / WHOIS Lookup">
    <div className="min-w-0 space-y-5">
      <p className="text-sm leading-6 text-zinc-300">On-demand registration information for one domain (including IDN), IPv4/IPv6 address, or AS-prefixed ASN. No monitoring or history.</p>
      <p className="text-sm leading-6 text-amber-200">Queries are sent through this site's backend to registration services. WHOIS uses unencrypted, unauthenticated TCP/43. Results may contain public contact information; downloads and clipboard copies are deliberate exports.</p>
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_240px]">
        <Field error={validation} description={classification || 'Examples: example.com, 8.8.8.8, 2606:4700:4700::1111, AS13335'}>
          <Label>Registration identifier</Label><FieldInput className={inputClass(!!validation)} value={target} maxLength={512} placeholder="Domain, IP address, or AS13335" onChange={(event) => setTarget(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && !loading && target && !validation) void run(); }} />
          <FieldError /><FieldDescription />
        </Field>
        <Field><Label>Protocol mode</Label><FieldSelect className={inputClass()} value={mode} onChange={(event) => setMode(event.target.value as RegistrationMode)}>
          <option value="auto">Auto</option><option value="rdap">RDAP-only</option><option value="whois">WHOIS-only</option>
        </FieldSelect></Field>
      </div>
      <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4"><summary className="cursor-pointer text-sm font-semibold">Protocol policy and limitations</summary>
        <p className="mt-3 text-sm leading-6 text-zinc-300">Auto tries RDAP first and uses WHOIS only when IANA has no HTTPS RDAP service, or the RDAP operation returns HTTP 405/501. Not-found, rate limits, denial, temporary failure, malformed replies, timeout, deadline exhaustion, cancellation, and blocked destinations never trigger fallback. Forced modes never switch protocols. Unknown WHOIS formats stay unknown. A no-match result does not mean a domain is available to purchase. Country is registration data, not verified geolocation; published DNSSEC is not live validation.</p>
      </details>
      <div className="flex flex-wrap gap-3">
        <button type="button" className="rounded-xl bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:bg-zinc-800 disabled:text-zinc-500" disabled={!target || !!validation || loading} aria-busy={loading} onClick={() => void run()}>{loading ? 'Looking up…' : 'Lookup'}</button>
        {loading && <CopyButton onClick={cancel}>Cancel lookup</CopyButton>}
        <CopyButton onClick={() => { owner.current?.abort(); owner.current = null; setLoading(false); setTarget(''); setMode('auto'); setResponse(null); setError(''); image.clearCopyImageStatus(); }}>Reset</CopyButton>
      </div>
      {(error || response?.ok === false) && <div role="alert" className="rounded-2xl border border-red-400/30 bg-red-400/10 p-4 text-sm text-red-200">{error || (response?.ok === false ? `${response.error.code}: ${response.error.message}` : '')}</div>}
      {result && <>
        <div className="flex flex-wrap gap-3">
          <CopyButton onClick={() => void structured.copy()}>{structured.copied ? 'Copied structured result' : 'Copy structured result'}</CopyButton>
          <CopyButton onClick={() => downloadRegistration(JSON.stringify(normalizedExport(result), null, 2), 'registration-normalized.json', 'application/json')}>Download normalized JSON</CopyButton>
          <CopyButton onClick={() => downloadRegistration(JSON.stringify({ query: result.input, protocol: result.protocol, source: result.source, timestamp: result.timestamp, attempts: result.attempts, cache: result.cache, rawResponses: result.rawResponses }, null, 2), 'registration-raw-with-metadata.json', 'application/json')}>Download raw with metadata</CopyButton>
          <ResultImageCopyControls status={image.copyImageStatus} onCopy={() => void image.copyResultImage()} />
        </div>
        <p role="status" className="text-sm text-red-200">{structured.error}</p>
        <RegistrationOverview result={result} calculatedAt={calculatedAt} />
        <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4"><summary className="cursor-pointer font-semibold">Contacts, events, DNSSEC, notices and unknown fields</summary><CommandBlock scrollInside>{JSON.stringify({ details: result.normalized.details, unknown: result.normalized.unknown, conflicts: result.normalized.conflicts }, null, 2)}</CommandBlock></details>
        <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4"><summary className="cursor-pointer font-semibold">Discovery freshness and normalized JSON</summary><CommandBlock scrollInside>{JSON.stringify(normalizedExport(result), null, 2)}</CommandBlock></details>
        <ResultImageCapture captureRef={image.imageRef}><RegistrationOverview result={result} calculatedAt={calculatedAt} image /></ResultImageCapture>
      </>}
      {response && <RegistrationDiagnostics attempts={response.attempts} rawResponses={response.rawResponses} />}
    </div>
  </Panel>;
}
