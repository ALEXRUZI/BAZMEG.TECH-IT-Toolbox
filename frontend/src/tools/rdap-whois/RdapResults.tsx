import { CopyButton } from '../../components/CopyButton';
import { CommandBlock } from '../../components/CommandBlock';
import { HttpHeaderExportItem, HttpHeaderExportSection, ResultImageHeader } from '../../components/ResultImageExport';
import { downloadRegistration, expirationRemaining, lookupTimestamp, publishedDnssec, registrationContactFields, registrationStatusExplanation, registrationOverviewFields, overviewValues } from './rdapHelpers';
import type { RegistrationAttempt, RegistrationRaw, RegistrationResult } from './rdapTypes';

export function RegistrationOverview({ result, calculatedAt, image = false }: { result: RegistrationResult; calculatedAt: number; image?: boolean }) {
  const domainOutcome = result.input.kind === 'domain' && result.outcome !== 'record';
  const metadata = {
    'Selected mode': ({ auto: 'Auto', rdap: 'RDAP-only', whois: 'WHOIS-only' })[result.input.protocolMode],
    'Protocol used': result.protocol.toUpperCase(), Source: result.source, 'Lookup timestamp': lookupTimestamp(result.timestamp),
    Cache: result.cache.cached ? `Cached result · ${result.cache.ageSeconds.toFixed(1)} seconds old; TTL ${result.cache.ttlSeconds}s` : 'Fresh lookup',
    Fallback: result.fallbackReason ?? 'None', Query: `${result.input.canonical} (${result.input.kind})`,
    Outcome: result.outcome === 'not_found' ? 'No matching registration record (not purchase availability)' : result.outcome === 'unknown' ? 'Unrecognized or conflicting WHOIS reply; inspect raw text' : 'Registration record',
  };
  return <div className="min-w-0 space-y-5">
    {image && <ResultImageHeader title="RDAP / WHOIS Lookup" />}
    <HttpHeaderExportSection title="Lookup metadata">
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">{Object.entries(metadata).map(([label, value]) => <div key={label} className="min-w-0">
        <dt className="text-xs font-semibold text-zinc-400">{label}</dt><dd className="mt-1 whitespace-pre-wrap [overflow-wrap:anywhere]">{value}</dd>
      </div>)}</dl>
    </HttpHeaderExportSection>
    {domainOutcome ? <HttpHeaderExportSection title={result.outcome === 'not_found' ? 'No registration record found' : 'Registration status could not be determined'}>
      <p className="text-lg font-semibold text-emerald-200 [overflow-wrap:anywhere]">{result.input.canonical}</p>
      <p className="mt-3 text-sm text-amber-200">{result.outcome === 'not_found'
        ? 'A missing registration record does not guarantee domain purchase or registration availability.'
        : 'The reply is unrecognized or conflicting. Inspect the detailed evidence, protocol attempts and raw responses for diagnostics.'}</p>
    </HttpHeaderExportSection> : <HttpHeaderExportSection title="Registration overview">
      <div className="grid min-w-0 gap-3 sm:grid-cols-2">
        {Object.entries(registrationOverviewFields(result)).map(([label, value]) => <div key={label} className={`min-w-0 ${label === 'Domain name' ? 'sm:col-span-2' : ''}`}><HttpHeaderExportItem label={label}>
          <span className={`whitespace-pre-wrap [overflow-wrap:anywhere] ${label === 'Domain name' ? 'text-2xl font-semibold text-emerald-200' : ''}`}>{value}</span>
        </HttpHeaderExportItem></div>)}
        {result.input.kind === 'domain' && <HttpHeaderExportItem label="Expiration remaining">{expirationRemaining(result, calculatedAt)}</HttpHeaderExportItem>}
      </div>
      {result.input.kind === 'domain' && <div className="mt-5 min-w-0 space-y-5">
        <div className="grid min-w-0 gap-5 lg:grid-cols-2">
          <DomainContact result={result} role="registrant" /><DomainContact result={result} role="registrar" />
        </div>
        <HttpHeaderExportSection title="Additional information">
          <div className="grid min-w-0 gap-3 sm:grid-cols-2">
            {['Created', 'Updated'].map((label) => <HttpHeaderExportItem key={label} label={label}><PublishedValues values={overviewValues(result, label)} /></HttpHeaderExportItem>)}
            <HttpHeaderExportItem label="Nameservers"><PublishedValues values={overviewValues(result, 'Nameservers')} /></HttpHeaderExportItem>
          </div>
          <PublishedDnssec result={result} />
        </HttpHeaderExportSection>
      </div>}
    </HttpHeaderExportSection>}
    <p className="text-sm text-amber-200">{result.warnings.join(' ')}</p>
    {result.normalized.conflicts.length > 0 && <p className="text-sm text-amber-200">Conflicting fields: {result.normalized.conflicts.join(', ')}. No value was selected as authoritative.</p>}
    {!image && <>
      <h3 className="font-semibold text-zinc-200">Detailed information</h3>
      <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
        <summary className="cursor-pointer font-semibold">All published fields and registry evidence</summary>
        <pre className="mt-3 whitespace-pre-wrap break-words text-sm [overflow-wrap:anywhere]">{JSON.stringify({ fields: result.normalized.fields, attribution: result.normalized.details.attribution ?? null, registryEvidence: result.normalized.details.registryEvidence ?? null }, null, 2)}</pre>
      </details>
      {result.input.kind === 'domain' && (result.normalized.fields.Status?.length ?? 0) > 0 && <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
        <summary className="cursor-pointer font-semibold">Registration status codes and explanations</summary>
        <p className="mt-3 text-xs text-zinc-400">ICANN EPP/RDAP definitions; not a live DNS or availability test.</p>
        <dl className="mt-3 space-y-3">{result.normalized.fields.Status.map((status, index) => <div key={index} className="min-w-0"><dt className="break-words font-mono text-sm [overflow-wrap:anywhere]">{status}</dt><dd className="mt-1 text-sm text-zinc-300">{registrationStatusExplanation(status)}</dd></div>)}</dl>
      </details>}
    </>}
  </div>;
}

function PublishedValues({ values }: { values: string[] }) {
  const published = values.filter((value) => value.trim());
  if (!published.length) return <>Unavailable</>;
  return <ul className="min-w-0 space-y-1">{published.map((value, index) => <li key={index} className="whitespace-pre-wrap [overflow-wrap:anywhere]">{value}</li>)}</ul>;
}

function DomainContact({ result, role }: { result: RegistrationResult; role: 'registrant' | 'registrar' }) {
  const fields = registrationContactFields(result, role);
  return <HttpHeaderExportSection title={role === 'registrant' ? 'Domain registrant' : 'Registrar'}>
    <dl className="min-w-0 space-y-3">{Object.entries(fields).map(([label, values]) => <div key={label} className="min-w-0">
      <dt className="text-xs font-semibold text-zinc-400">{label}</dt><dd className="mt-1 min-w-0 text-sm [overflow-wrap:anywhere]"><PublishedValues values={values} /></dd>
    </div>)}</dl>
    {Object.values(fields).some((values) => values.length > 1) && <p className="mt-3 text-xs text-amber-200">Multiple published values; no preference inferred. See detailed evidence for attribution.</p>}
  </HttpHeaderExportSection>;
}

function PublishedDnssec({ result }: { result: RegistrationResult }) {
  const dnssec = publishedDnssec(result);
  if (!dnssec) return null;
  return <div className="mt-5 min-w-0 space-y-3">
    <h5 className="font-semibold text-emerald-200">Published DNSSEC</h5>
    <p className="text-sm">{dnssec.status}</p>
    {dnssec.statuses.length > 0 && <PublishedValues values={dnssec.statuses} />}
    <p className="text-xs text-zinc-400">Published registry metadata only; the live DNSSEC chain has not been validated.</p>
    {dnssec.malformed && <p className="text-sm text-amber-200">Unrecognized or malformed DNSSEC fields; inspect the detailed data. No values inferred.</p>}
    <div className="grid min-w-0 gap-3 sm:grid-cols-2">{dnssec.records.map((record, index) => record && <section key={index} className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/70 p-4">
      <h6 className="text-sm font-semibold">DS Record #{index + 1}</h6>
      <dl className="mt-3 min-w-0 space-y-2">{Object.entries(record).map(([label, value]) => <div key={label} className="min-w-0 text-sm">
        <dt className="text-zinc-400">{label}</dt><dd className="min-w-0 whitespace-pre-wrap font-mono [overflow-wrap:anywhere]">{value}</dd>
      </div>)}</dl>
    </section>)}</div>
  </div>;
}

export function RegistrationDiagnostics({ attempts, rawResponses }: { attempts: RegistrationAttempt[]; rawResponses: RegistrationRaw[] }) {
  return <div className="min-w-0 space-y-4">
    <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4"><summary className="cursor-pointer font-semibold">Protocol attempts</summary>
      <CommandBlock scrollInside>{JSON.stringify(attempts, null, 2)}</CommandBlock>
    </details>
    <details className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4"><summary className="cursor-pointer font-semibold">Raw responses</summary>
      {rawResponses.map((raw, index) => <section key={index} className="mt-4 min-w-0 space-y-3">
        <h3 className="break-words text-sm font-semibold [overflow-wrap:anywhere]">{raw.protocol.toUpperCase()} · {raw.phase} · {raw.source} · {raw.timestamp}</h3>
        <CommandBlock scrollInside>{raw.text}</CommandBlock>
        <CopyButton onClick={() => downloadRegistration(raw.text, `registration-${index + 1}.${raw.protocol === 'rdap' ? 'json' : 'txt'}`, raw.protocol === 'rdap' ? 'application/json' : 'text/plain')}>Download raw {raw.protocol.toUpperCase()}</CopyButton>
      </section>)}
    </details>
  </div>;
}
