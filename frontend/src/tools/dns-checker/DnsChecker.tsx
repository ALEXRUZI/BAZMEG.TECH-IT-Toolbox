import { useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { CommandBlock } from '../../components/CommandBlock';
import { ExampleTextInput, Field, Label, Panel, ResultItem, inputClass, FieldSelect, FieldError } from '../../components/Panel';
import { DnsStringList, HttpHeaderExportDetailRow, HttpHeaderExportItem, HttpHeaderExportSection, ResultImageCapture, ResultImageCopyControls, ResultImageHeader, TlsResultSection, useResultImageClipboard } from '../../components/ResultImageExport';
import { fetchDnsCheck } from './dnsApi';
import { asDnsDiagnostics, asDnsProviders, asDnsRecords, asDnsStrings, buildDnsPayload, describeDnsSpfMechanism, formatDiagnosticName, formatDnsLowestTtl, formatDnsRecord, formatDnsRecordValues, formatDnsResolver, formatDnsStatus, formatDnsTtlShort, formatDnsTtls, formatMilliseconds, formatSeconds, formatUnknown, getDnsDiagnosticId, getDnsExportTarget, getDnsPreviewName, getDnsSpfDiagnostics, getDnsSpfMechanismWarning, getDnsSpfMechanisms, getDnsSpfTtl, getDnsTxtDiagnostics, shouldShowDnsValidationError, validateDnsForm } from './dnsHelpers';
import type { DnsCacheMetadata, DnsCheckErrorResponse, DnsCheckResult, DnsDiagnostic, DnsMode, DnsProviderResult, DnsProviderSummary, DnsRecord, DnsRecordType, DnsResponseView, DnsSpfMechanism, DnsTxtHelper } from './dnsTypes';
const dnsRecordTypes: DnsRecordType[] = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'PTR', 'SRV'];
const dnsSingleResolvers: DnsProviderSummary[] = [
  { id: 'cloudflare', name: 'Cloudflare DNS' },
  { id: 'google', name: 'Google DNS' },
  { id: 'opendns', name: 'OpenDNS / Cisco' },
  { id: 'quad9', name: 'Quad9' },
  { id: 'fortiguard', name: 'FortiGuard DNS' },
  { id: 'adguard', name: 'AdGuard DNS' },
  { id: 'verisign', name: 'Verisign Public DNS' },
  { id: 'dnswatch', name: 'DNS.WATCH' },
  { id: 'comodo', name: 'Comodo Secure DNS' },
  { id: 'level3', name: 'Level3 / Lumen' },
  { id: 'neustar', name: 'Neustar UltraDNS' },
];
const dnsTxtHelperLabels: Record<DnsTxtHelper, string> = {
  normal: 'Normal TXT',
  spf: 'SPF',
  dkim: 'DKIM',
  dmarc: 'DMARC',
  acme: 'ACME challenge',
};
export function DnsChecker() {
  const [mode, setMode] = useState<DnsMode>('single');
  const [recordType, setRecordType] = useState<DnsRecordType>('A');
  const [resolverId, setResolverId] = useState('cloudflare');
  const [queryInput, setQueryInput] = useState('');
  const [txtHelper, setTxtHelper] = useState<DnsTxtHelper>('normal');
  const [dkimSelector, setDkimSelector] = useState('');
  const [srvService, setSrvService] = useState('');
  const [srvProtocol, setSrvProtocol] = useState<'tcp' | 'udp'>('tcp');
  const [srvDomain, setSrvDomain] = useState('');
  const [dnssec, setDnssec] = useState(true);
  const [responseView, setResponseView] = useState<DnsResponseView>('simple');
  const [result, setResult] = useState<DnsCheckResult | null>(null);
  const [error, setError] = useState<DnsCheckErrorResponse['error'] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const {
    imageRef: dnsImageRef,
    copyImageStatus,
    copyResultImage: copyDnsResultImage,
    clearCopyImageStatus,
  } = useResultImageClipboard('Copied DNS result image to clipboard.');
  const validationError = validateDnsForm(recordType, queryInput, txtHelper, dkimSelector, srvService, srvDomain);
  const previewName = getDnsPreviewName(recordType, queryInput, txtHelper, dkimSelector, srvService, srvProtocol, srvDomain);
  async function runDnsCheck() {
    const payload = buildDnsPayload({
      mode,
      recordType,
      resolverId,
      queryInput,
      txtHelper,
      dkimSelector,
      srvService,
      srvProtocol,
      srvDomain,
      dnssec,
    });
    setIsLoading(true);
    setResult(null);
    setError(null);
    clearCopyImageStatus();
    try {
      const { response, body } = await fetchDnsCheck(payload);
      if ('error' in body && body.error) {
        setError(body.error);
        return;
      }
      if (!response.ok) {
        const nextError = {
          code: 'DNS_CHECK_FAILED',
          message: 'DNS check failed.',
        };
        setError(nextError);
        return;
      }
      setResult(body);
    } catch {
      setError({
        code: 'DNS_CHECK_FAILED',
        message: 'DNS check failed.',
      });
    } finally {
      setIsLoading(false);
    }
  }
  return (
    <Panel title="DNS checker">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Query DNS records through predefined providers, then switch views locally without running another check.
      </p>
      <div className="mt-5 flex flex-wrap gap-2">
        {[
          ['single', 'Single DNS Provider Check'],
          ['burst', 'Burst / Multi-Provider DNS Comparison'],
        ].map(([value, label]) => (
          <button
            key={value}
            className={`rounded-full border px-4 py-2 text-sm font-semibold transition ${
              mode === value
                ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-100'
                : 'border-white/10 bg-zinc-950/60 text-zinc-300 hover:border-emerald-400/40 hover:text-emerald-200'
            }`}
            type="button"
            onClick={() => setMode(value as DnsMode)}
          >
            {label}
          </button>
        ))}
      </div>
      <DnsCacheNote mode={mode} />
      <div className="mt-5 grid gap-4 xl:grid-cols-[180px_minmax(0,1fr)]">
        <Field>
          <Label>
            <span className="mb-2 block">Record type</span>
            <FieldSelect
              className={inputClass()}
              value={recordType}
              onChange={(event) => setRecordType(event.target.value as DnsRecordType)}
            >
              {dnsRecordTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </FieldSelect>
          </Label>
        </Field>
        {mode === 'single' && (
          <Field>
            <Label>
              <span className="mb-2 block">DNS provider</span>
              <FieldSelect className={inputClass()} value={resolverId} onChange={(event) => setResolverId(event.target.value)}>
                {dnsSingleResolvers.map((resolver) => (
                  <option key={resolver.id} value={resolver.id}>
                    {resolver.name}
                  </option>
                ))}
              </FieldSelect>
            </Label>
          </Field>
        )}
      </div>
      <div className="mt-4">
        <DnsRecordInput
          dkimSelector={dkimSelector}
          queryInput={queryInput}
          recordType={recordType}
          srvDomain={srvDomain}
          srvProtocol={srvProtocol}
          srvService={srvService}
          txtHelper={txtHelper}
          validationError={validationError}
          onDkimSelectorChange={setDkimSelector}
          onQueryChange={setQueryInput}
          onSrvDomainChange={setSrvDomain}
          onSrvProtocolChange={setSrvProtocol}
          onSrvServiceChange={setSrvService}
          onTxtHelperChange={setTxtHelper}
        />
      </div>
      {previewName && (
        <div className="mt-4 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Generated query name</p>
          <p className="mt-2 break-words font-mono text-sm text-emerald-200">{previewName}</p>
        </div>
      )}
      {mode === 'single' && (
        <label className="mt-4 flex items-center gap-3 text-sm font-medium text-zinc-300">
          <input
            checked={dnssec}
            className="size-4 accent-emerald-500"
            type="checkbox"
            onChange={(event) => setDnssec(event.target.checked)}
          />
          Request DNSSEC diagnostics
        </label>
      )}
      <div className="mt-5">
        <button
          className="rounded-xl border border-emerald-500/35 bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition hover:border-emerald-300 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800 disabled:text-zinc-500"
          type="button"
          onClick={() => void runDnsCheck()}
          disabled={Boolean(validationError) || isLoading}
          aria-busy={isLoading}
        >
          {isLoading ? 'Running...' : 'Run DNS Check'}
        </button>
      </div>
      {result && <DnsCacheStatusNotice cache={result.cache} />}
      {result && (
        <div className="mt-4">
          <ResultImageCopyControls
            status={copyImageStatus}
            onCopy={() => void copyDnsResultImage()}
          />
        </div>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-zinc-300">Response view:</span>
        {(['simple', 'advanced', 'raw'] as const).map((view) => (
          <button
            key={view}
            className={`rounded-full border px-3 py-1.5 text-sm font-semibold capitalize transition ${
              responseView === view
                ? 'border-emerald-400/60 bg-emerald-500/20 text-emerald-100'
                : 'border-white/10 bg-zinc-950/60 text-zinc-300 hover:border-emerald-400/40 hover:text-emerald-200'
            }`}
            type="button"
            onClick={() => setResponseView(view)}
          >
            {view}
          </button>
        ))}
      </div>
      {error && <DnsErrorBox error={error} />}
      {result && (
        <div className="mt-6">
          {responseView === 'simple' && <DnsSimpleView result={result} />}
          {responseView === 'advanced' && <DnsAdvancedView result={result} />}
          {responseView === 'raw' && <CommandBlock scrollInside>{JSON.stringify(result, null, 2)}</CommandBlock>}
          <ResultImageCapture captureRef={dnsImageRef}>
            <DnsResultImageExport result={result} />
          </ResultImageCapture>
        </div>
      )}
    </Panel>
  );
}
function DnsCacheNote({ mode }: { mode: DnsMode }) {
  return (
    <div className="mt-5 space-y-3">
      <div className="rounded-2xl border border-emerald-400/25 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
        {mode === 'single'
          ? 'Single-provider DNS checks are cached by this site for 60 seconds for the exact same query. Cached results are clearly marked with cache age and expiry.'
          : 'Multi-provider DNS checks query several predefined DNS providers and are cached by this site for 5 minutes. Cached results can usually be shown without making another live DNS request.'}
      </div>
      {mode === 'burst' && (
        <div className="rounded-2xl border border-amber-300/25 bg-amber-400/10 p-4 text-sm leading-6 text-amber-100">
          Deep DNSSEC diagnostics are disabled in Multi-Provider mode to keep results fast, reduce backend load, and prevent abuse. Use Single Provider mode for full DNSSEC diagnostics.
        </div>
      )}
    </div>
  );
}
function DnsRecordInput({
  dkimSelector,
  queryInput,
  recordType,
  srvDomain,
  srvProtocol,
  srvService,
  txtHelper,
  validationError,
  onDkimSelectorChange,
  onQueryChange,
  onSrvDomainChange,
  onSrvProtocolChange,
  onSrvServiceChange,
  onTxtHelperChange,
}: {
  dkimSelector: string;
  queryInput: string;
  recordType: DnsRecordType;
  srvDomain: string;
  srvProtocol: 'tcp' | 'udp';
  srvService: string;
  txtHelper: DnsTxtHelper;
  validationError: string;
  onDkimSelectorChange: (value: string) => void;
  onQueryChange: (value: string) => void;
  onSrvDomainChange: (value: string) => void;
  onSrvProtocolChange: (value: 'tcp' | 'udp') => void;
  onSrvServiceChange: (value: string) => void;
  onTxtHelperChange: (value: DnsTxtHelper) => void;
}) {
  const errorId = useId();
  const visibleValidationError = shouldShowDnsValidationError(recordType, queryInput, txtHelper, dkimSelector, srvService, srvDomain)
    ? validationError
    : '';
  if (recordType === 'SRV') {
    return (
      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_140px_minmax(0,1fr)]">
        <Field>
          <Label>
            <span className="mb-2 block">Service</span>
            <ExampleTextInput
              example="sip"
              aria-describedby={visibleValidationError ? errorId : undefined}
              hasError={Boolean(visibleValidationError)}
              value={srvService}
              onChange={onSrvServiceChange}
            />
          </Label>
        </Field>
        <Field>
          <Label>
            <span className="mb-2 block">Protocol</span>
            <FieldSelect
              className={inputClass()}
              value={srvProtocol}
              onChange={(event) => onSrvProtocolChange(event.target.value as 'tcp' | 'udp')}
            >
              <option value="tcp">_tcp</option>
              <option value="udp">_udp</option>
            </FieldSelect>
          </Label>
        </Field>
        <Field>
          <Label>
            <span className="mb-2 block">Domain</span>
            <ExampleTextInput
              example="example.com"
              aria-describedby={visibleValidationError ? errorId : undefined}
              hasError={Boolean(visibleValidationError)}
              value={srvDomain}
              onChange={onSrvDomainChange}
            />
          </Label>
        </Field>
        {visibleValidationError && <p id={errorId} className="text-xs leading-5 text-red-300 md:col-span-3">{visibleValidationError}</p>}
      </div>
    );
  }
  if (recordType === 'TXT') {
    return (
      <div className="grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
        <Field>
          <Label>
            <span className="mb-2 block">TXT helper</span>
            <FieldSelect
              className={inputClass()}
              value={txtHelper}
              onChange={(event) => onTxtHelperChange(event.target.value as DnsTxtHelper)}
            >
              {(Object.keys(dnsTxtHelperLabels) as DnsTxtHelper[]).map((helper) => (
                <option key={helper} value={helper}>
                  {dnsTxtHelperLabels[helper]}
                </option>
              ))}
            </FieldSelect>
          </Label>
        </Field>
        <Field>
          <Label>
            <span className="mb-2 block">{txtHelper === 'dkim' ? 'Domain' : 'Domain/FQDN'}</span>
            <ExampleTextInput
              example="example.com"
              aria-describedby={visibleValidationError ? errorId : undefined}
              hasError={Boolean(visibleValidationError)}
              value={queryInput}
              onChange={onQueryChange}
            />
          </Label>
        </Field>
        {txtHelper === 'dkim' && (
          <Field>
            <Label>
              <span className="mb-2 block">Selector</span>
              <ExampleTextInput
                example="selector1"
                aria-describedby={visibleValidationError ? errorId : undefined}
                hasError={Boolean(visibleValidationError)}
                value={dkimSelector}
                onChange={onDkimSelectorChange}
              />
            </Label>
          </Field>
        )}
        {visibleValidationError && (
          <p id={errorId} className={`text-xs leading-5 text-red-300 ${txtHelper === 'dkim' ? 'md:col-span-2' : 'md:col-span-2'}`}>
            {visibleValidationError}
          </p>
        )}
      </div>
    );
  }
  return (
    <Field error={visibleValidationError}>
      <Label>
        <span className="mb-2 block">{recordType === 'PTR' ? 'IP address' : 'Domain/FQDN'}</span>
        <ExampleTextInput
          example={recordType === 'PTR' ? '8.8.8.8' : 'example.com'}
          hasError={Boolean(visibleValidationError)}
          value={queryInput}
          onChange={onQueryChange}
        />
      </Label>
      <FieldError />
    </Field>
  );
}
function DnsErrorBox({ error }: { error: DnsCheckErrorResponse['error'] }) {
  const message = error.code === 'RATE_LIMITED'
    ? 'Rate limit reached. Too many live DNS checks were made recently. Please try again later. Cached DNS results may still be available for repeated checks.'
    : error.message;
  return (
    <div role="alert" className="mt-5 rounded-2xl border border-red-300/35 bg-red-950/40 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Error</p>
      <p className="mt-2 text-sm leading-6 text-red-50">{message}</p>
    </div>
  );
}
function DnsSimpleView({ result }: { result: DnsCheckResult }) {
  const records = result.mode === 'burst' ? [] : asDnsRecords(result.records);
  const providers = asDnsProviders(result.providers);
  const diagnostics = asDnsDiagnostics(result.diagnostics);
  const warnings = asDnsStrings(result.warnings);
  const txtDiagnostics = getDnsTxtDiagnostics(diagnostics);
  const hasSpfExplanation = result.mode === 'single' && getDnsSpfDiagnostics(txtDiagnostics).length > 0;
  return (
    <div className="min-w-0 space-y-5">
      <TlsResultSection title="Result">
        {!result.ok && <p role="alert" className="mb-3 text-sm text-amber-100">{formatDnsStatus(result.status)}. This diagnostic does not establish a complete successful lookup.</p>}
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <ResultItem label="Overall result" value={formatDnsStatus(result.status)} />
          <ResultItem label="Response code" value={formatUnknown(result.responseCode)} />
          <ResultItem label="Resolver/provider" value={formatDnsResolver(result)} />
          <ResultItem label="Duration" value={formatMilliseconds(result.durationMs)} />
          <ResultItem label="Requested record" value={`${result.query.queryName} (${result.query.recordType})`} />
        </div>
      </TlsResultSection>
      {result.mode === 'burst' ? (
        <DnsProviderComparison providers={providers} />
      ) : (
        <TlsResultSection title="Main records">
          <DnsRecordList records={records} emptyText="No requested records were returned." />
        </TlsResultSection>
      )}
      {warnings.length > 0 && (
        <TlsResultSection title="Important warnings">
          <DnsStringList values={warnings} />
        </TlsResultSection>
      )}
      {hasSpfExplanation && (
        <TlsResultSection title="TXT/email diagnostics">
          <DnsTxtDiagnostics diagnostics={txtDiagnostics} records={records} compact />
        </TlsResultSection>
      )}
      {diagnostics.length > 0 && (
        <TlsResultSection title="Important diagnostics">
          <DnsDiagnosticList diagnostics={diagnostics.slice(0, 6)} />
        </TlsResultSection>
      )}
    </div>
  );
}
function DnsAdvancedView({ result }: { result: DnsCheckResult }) {
  const answer = asDnsRecords(result.answer);
  const authority = asDnsRecords(result.authority);
  const additional = asDnsRecords(result.additional);
  const providers = asDnsProviders(result.providers);
  const diagnostics = asDnsDiagnostics(result.diagnostics);
  const warnings = asDnsStrings(result.warnings);
  const cnameRecords = answer.filter((record) => record.type === 'CNAME');
  const mxDiagnostics = diagnostics.filter((diagnostic) => {
    const diagnosticId = getDnsDiagnosticId(diagnostic);
    return diagnosticId.startsWith('mx_') || diagnosticId.includes('mx');
  });
  const txtDiagnostics = getDnsTxtDiagnostics(diagnostics);
  return (
    <div className="min-w-0 space-y-5">
      <TlsResultSection title="Query">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <ResultItem label="Input" value={result.query?.input} />
          <ResultItem label="Query name" value={result.query?.queryName} />
          <ResultItem label="Record type" value={result.query?.recordType} />
          <ResultItem label="Service" value={result.query?.service} />
          <ResultItem label="Protocol" value={result.query?.protocol} />
          <ResultItem label="Domain" value={result.query?.domain} />
        </div>
      </TlsResultSection>
      <TlsResultSection title="Response metadata">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <ResultItem label="Status" value={formatDnsStatus(result.status)} />
          <ResultItem label="Response code" value={formatUnknown(result.responseCode)} />
          <ResultItem label="Duration" value={formatMilliseconds(result.durationMs)} />
          <ResultItem label="Mode" value={result.mode} />
        </div>
      </TlsResultSection>
      <TlsResultSection title="Resolver metadata">
        <pre className="max-w-full whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-zinc-950 p-4 text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
          {JSON.stringify({ resolver: result.resolver, provider: result.provider }, null, 2)}
        </pre>
      </TlsResultSection>
      {result.mode === 'burst' && <DnsProviderComparison providers={providers} />}
      <TlsResultSection title="Answer section">
        <DnsRecordList records={answer} emptyText="No answer records were returned." />
      </TlsResultSection>
      <TlsResultSection title="Authority section">
        <DnsRecordList records={authority} emptyText="No authority records were returned." />
      </TlsResultSection>
      <TlsResultSection title="Additional section">
        <DnsRecordList records={additional} emptyText="No additional records were returned." />
      </TlsResultSection>
      <TlsResultSection title="DNSSEC diagnostics">
        <pre className="max-w-full whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-zinc-950 p-4 text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
          {JSON.stringify(result.dnssec, null, 2)}
        </pre>
      </TlsResultSection>
      {mxDiagnostics.length > 0 && (
        <TlsResultSection title="MX diagnostics">
          <DnsDiagnosticList diagnostics={mxDiagnostics} />
        </TlsResultSection>
      )}
      {result.mode === 'single' && txtDiagnostics.length > 0 && (
        <TlsResultSection title="TXT/email diagnostics">
          <DnsTxtDiagnostics diagnostics={txtDiagnostics} records={answer} warnings={warnings} />
        </TlsResultSection>
      )}
      {cnameRecords.length > 0 && (
        <TlsResultSection title="CNAME chain">
          <DnsRecordList records={cnameRecords} emptyText="No CNAME records were returned." />
        </TlsResultSection>
      )}
      <TlsResultSection title="All diagnostics">
        <DnsDiagnosticList diagnostics={diagnostics} />
      </TlsResultSection>
      <TlsResultSection title="All warnings">
        <DnsStringList values={warnings} />
      </TlsResultSection>
    </div>
  );
}
function DnsResultImageExport({ result }: { result: DnsCheckResult }) {
  const records = result.mode === 'burst' ? [] : asDnsRecords(result.records);
  const providers = asDnsProviders(result.providers);
  const diagnostics = asDnsDiagnostics(result.diagnostics).slice(0, 6);
  const warnings = asDnsStrings(result.warnings);
  const txtDiagnostics = getDnsTxtDiagnostics(asDnsDiagnostics(result.diagnostics));
  const hasSpfExplanation = result.mode === 'single' && getDnsSpfDiagnostics(txtDiagnostics).length > 0;
  return (
    <div className="min-w-0 bg-[#0f1117] text-zinc-100">
      <ResultImageHeader title="DNS Checker" />
      <div className="mt-6 min-w-0 space-y-5">
        <HttpHeaderExportSection title="Query summary">
          <div className="grid min-w-0 grid-cols-2 gap-3">
            <HttpHeaderExportItem label="DNS target">{getDnsExportTarget(result)}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Record type">{result.query?.recordType || '-'}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Resolver/provider">{formatDnsResolver(result)}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Mode">{result.mode === 'burst' ? 'Multi-provider comparison' : 'Single provider'}</HttpHeaderExportItem>
          </div>
        </HttpHeaderExportSection>
        <HttpHeaderExportSection title="Response summary">
          <div className="grid min-w-0 grid-cols-2 gap-3">
            <HttpHeaderExportItem label="Overall result">{formatDnsStatus(result.status) || '-'}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Response code">{formatUnknown(result.responseCode)}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Lowest TTL">{result.mode === 'burst' ? 'See provider answers' : formatDnsLowestTtl(records)}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Duration">{formatMilliseconds(result.durationMs)}</HttpHeaderExportItem>
          </div>
        </HttpHeaderExportSection>
        {result.mode === 'burst' ? (
          <HttpHeaderExportSection title="Provider answers">
            <div className="min-w-0 space-y-4">
              {providers.length > 0 ? providers.map((provider, index) => (
                <DnsExportProviderCard key={`${provider.resolver?.id || provider.provider?.id || 'provider'}-${index}`} provider={provider} />
              )) : (
                <p className="text-sm leading-6 text-zinc-400">No provider comparison data was returned.</p>
              )}
            </div>
          </HttpHeaderExportSection>
        ) : (
          <HttpHeaderExportSection title="Answers">
            <DnsExportRecordList records={records} emptyText="No requested records were returned." />
          </HttpHeaderExportSection>
        )}
        {warnings.length > 0 && (
          <HttpHeaderExportSection title="Important warnings">
            <DnsStringList values={warnings} />
          </HttpHeaderExportSection>
        )}
        {hasSpfExplanation && (
          <HttpHeaderExportSection title="TXT/email diagnostics">
            <DnsTxtDiagnostics diagnostics={txtDiagnostics} records={records} compact />
          </HttpHeaderExportSection>
        )}
        {diagnostics.length > 0 && (
          <HttpHeaderExportSection title="Important diagnostics">
            <DnsExportDiagnosticList diagnostics={diagnostics} />
          </HttpHeaderExportSection>
        )}
      </div>
    </div>
  );
}
function DnsExportProviderCard({ provider }: { provider: DnsProviderResult }) {
  const resolver = provider.resolver || provider.provider;
  const records = asDnsRecords(provider.records);
  const warnings = asDnsStrings(provider.warnings);
  return (
    <article className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h5 className="break-words text-base font-semibold text-zinc-50 [overflow-wrap:anywhere]">
            {resolver?.name || 'Unknown provider'}
          </h5>
          <p className="mt-1 break-words text-xs uppercase tracking-[0.14em] text-zinc-500 [overflow-wrap:anywhere]">
            {resolver?.profile || resolver?.category || 'Provider'}
          </p>
        </div>
        <span className={`w-fit rounded-full border px-3 py-1 text-xs font-semibold ${dnsBadgeClass(provider)}`}>
          {formatDnsStatus(provider.status) || 'Unknown'}
        </span>
      </div>
      <dl className="mt-4 min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
        <HttpHeaderExportDetailRow label="Response code">{provider.responseCode || provider.status || '-'}</HttpHeaderExportDetailRow>
        <HttpHeaderExportDetailRow label="Lowest TTL">{formatDnsLowestTtl(records)}</HttpHeaderExportDetailRow>
        <HttpHeaderExportDetailRow label="Answers">{formatDnsRecordValues(records)}</HttpHeaderExportDetailRow>
        <HttpHeaderExportDetailRow label="Warnings">{warnings.length ? warnings.join(' ') : '-'}</HttpHeaderExportDetailRow>
      </dl>
    </article>
  );
}
function DnsExportRecordList({ records, emptyText }: { records?: DnsRecord[] | null; emptyText: string }) {
  const safeRecords = asDnsRecords(records);
  if (safeRecords.length === 0) {
    return <p className="text-sm leading-6 text-zinc-400">{emptyText}</p>;
  }
  return (
    <div className="min-w-0 space-y-3">
      {safeRecords.map((record, index) => (
        <article key={`${record.name || 'record'}-${record.type || 'unknown'}-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
          <dl className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
            <HttpHeaderExportDetailRow label="Type">{record.type || 'Record'}</HttpHeaderExportDetailRow>
            <HttpHeaderExportDetailRow label="Name">{record.name || '-'}</HttpHeaderExportDetailRow>
            <HttpHeaderExportDetailRow label="TTL">{record.ttl === undefined ? '-' : `${record.ttl} seconds`}</HttpHeaderExportDetailRow>
            <HttpHeaderExportDetailRow label="Value">{formatDnsRecord(record)}</HttpHeaderExportDetailRow>
          </dl>
        </article>
      ))}
    </div>
  );
}
function DnsExportDiagnosticList({ diagnostics }: { diagnostics?: DnsDiagnostic[] | null }) {
  const safeDiagnostics = asDnsDiagnostics(diagnostics);
  if (safeDiagnostics.length === 0) {
    return <p className="text-sm leading-6 text-zinc-400">No diagnostics were returned.</p>;
  }
  return (
    <div className="min-w-0 space-y-3">
      {safeDiagnostics.map((diagnostic, index) => {
        const diagnosticId = getDnsDiagnosticId(diagnostic);
        return (
          <article key={`${diagnosticId}-${index}`} className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/70 p-4">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <p className="break-words font-mono text-sm font-semibold text-zinc-100 [overflow-wrap:anywhere]">
                {formatDiagnosticName(diagnosticId)}
              </p>
              {diagnostic.status && (
                <span className="rounded-full border border-white/10 bg-zinc-900 px-2 py-0.5 text-xs font-semibold text-zinc-300">
                  {diagnostic.status}
                </span>
              )}
            </div>
            <p className="mt-2 break-words text-sm leading-6 text-zinc-300 [overflow-wrap:anywhere]">
              {diagnostic.message || 'No important diagnostics were reported.'}
            </p>
          </article>
        );
      })}
    </div>
  );
}
function DnsCacheStatusNotice({ cache }: { cache: DnsCacheMetadata }) {
  const cacheDetails = [
    ['Served from this site\'s cache', cache.fromCache ? 'Yes' : 'No'],
    ['Cache age', formatSeconds(cache.cacheAgeSeconds)],
    ['Expires in', formatSeconds(cache.cacheExpiresInSeconds)],
    ['Cache TTL', formatSeconds(cache.cacheTtlSeconds)],
  ].filter((detail): detail is [string, string] => Boolean(detail[1]));
  return (
    <aside className="mt-4 rounded-2xl border border-emerald-400/25 bg-emerald-500/10 p-4 text-sm text-emerald-50">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-200">Cache status</p>
          <p className="mt-1 font-semibold text-emerald-50">
            {cache.fromCache ? 'Served from this site\'s cache' : 'Live DNS check'}
          </p>
        </div>
        <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
          {cacheDetails.map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200/80">{label}</dt>
              <dd className="mt-0.5 font-mono text-sm text-emerald-50">{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </aside>
  );
}
function DnsProviderComparison({ providers }: { providers?: DnsProviderResult[] | null }) {
  const safeProviders = asDnsProviders(providers);
  if (safeProviders.length === 0) {
    return (
      <TlsResultSection title="Provider comparison">
        <p className="text-sm text-zinc-400">No provider comparison data was returned.</p>
      </TlsResultSection>
    );
  }
  return (
    <TlsResultSection title="Provider comparison">
      <div className="grid min-w-0 gap-3">
        {safeProviders.map((provider, index) => {
          const resolver = provider.resolver || provider.provider;
          const records = asDnsRecords(provider.records);
          const warnings = asDnsStrings(provider.warnings);
          return (
            <article key={resolver?.id || `provider-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
              <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                <div className="min-w-0">
                  <h4 className="break-words text-sm font-semibold text-zinc-100 [overflow-wrap:anywhere]">
                    {resolver?.name || 'Unknown provider'}
                  </h4>
                  <p className="mt-1 break-words text-xs uppercase tracking-[0.14em] text-zinc-500 [overflow-wrap:anywhere]">
                    {resolver?.profile || resolver?.category || 'Provider'}
                  </p>
                </div>
                <span className={`w-fit rounded-full border px-3 py-1 text-xs font-semibold ${dnsBadgeClass(provider)}`}>
                  {formatDnsStatus(provider.status) || 'Unknown'}
                </span>
              </div>
              <dl className="mt-4 grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-3">
                <DnsDetailItem label="Response" value={provider.responseCode || provider.status || '-'} mono />
                <DnsDetailItem label="Records" value={formatDnsRecordValues(records)} />
                <DnsDetailItem label="TTL" value={formatDnsTtls(records)} mono />
                <DnsDetailItem label="Duration" value={formatMilliseconds(provider.durationMs) || '-'} mono />
                <DnsDetailItem label="Warnings" value={warnings.length ? warnings.join(' ') : '-'} />
              </dl>
            </article>
          );
        })}
      </div>
    </TlsResultSection>
  );
}
function dnsBadgeClass(provider: DnsProviderResult) {
  return provider.ok && provider.status === 'ok'
    ? 'border-emerald-400/25 bg-emerald-500/10 text-emerald-200'
    : 'border-amber-300/25 bg-amber-400/10 text-amber-100';
}

function DnsRecordList({ records, emptyText }: { records?: DnsRecord[] | null; emptyText: string }) {
  const safeRecords = asDnsRecords(records);
  if (safeRecords.length === 0) {
    return <p className="text-sm text-zinc-400">{emptyText}</p>;
  }
  return (
    <div className="min-w-0 space-y-3">
      {safeRecords.map((record, index) => (
        <article key={`${record.name || 'record'}-${record.type || 'unknown'}-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <dl className="grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <DnsDetailItem label="Type" value={record.type || 'Record'} />
            <DnsDetailItem label="Name" value={record.name || '-'} mono />
            <DnsDetailItem label="TTL" value={record.ttl === undefined ? '-' : `${record.ttl} seconds`} mono />
            <DnsDetailItem label="Value" value={formatDnsRecord(record)} mono />
            {record.type === 'MX' && (
              <>
                <DnsDetailItem label="Preference" value={formatUnknown(record.preference) || '-'} mono />
                <DnsDetailItem label="Exchange" value={record.exchange || '-'} mono />
                <DnsDetailItem label="Resolved A records" value={record.resolvedA?.join(', ') || '-'} mono />
                <DnsDetailItem label="Resolved AAAA records" value={record.resolvedAAAA?.join(', ') || '-'} mono />
              </>
            )}
          </dl>
        </article>
      ))}
    </div>
  );
}
function DnsDetailItem({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500">{label}</dt>
      <dd className={`mt-1 break-words text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere] ${mono ? 'font-mono' : ''}`}>
        {value || '-'}
      </dd>
    </div>
  );
}
function DnsDiagnosticList({ diagnostics }: { diagnostics?: DnsDiagnostic[] | null }) {
  const safeDiagnostics = asDnsDiagnostics(diagnostics);
  if (safeDiagnostics.length === 0) {
    return <p className="text-sm text-zinc-400">No diagnostics were returned.</p>;
  }
  return (
    <div className="min-w-0 space-y-3">
      {safeDiagnostics.map((diagnostic, index) => {
        const diagnosticId = getDnsDiagnosticId(diagnostic);
        return (
          <div key={`${diagnosticId}-${index}`} className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/60 p-4">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <p className="break-words font-mono text-sm font-semibold text-zinc-100 [overflow-wrap:anywhere]">
                {formatDiagnosticName(diagnosticId)}
              </p>
              {diagnostic.status && (
                <span className="rounded-full border border-white/10 bg-zinc-900 px-2 py-0.5 text-xs font-semibold text-zinc-300">
                  {diagnostic.status}
                </span>
              )}
            </div>
            {diagnostic.message && (
              <p className="mt-2 break-words text-sm leading-6 text-zinc-300 [overflow-wrap:anywhere]">{diagnostic.message}</p>
            )}
            <pre className="mt-3 max-w-full whitespace-pre-wrap break-words text-xs leading-5 text-zinc-300 [overflow-wrap:anywhere]">
              {JSON.stringify(diagnostic, null, 2)}
            </pre>
          </div>
        );
      })}
    </div>
  );
}
function DnsTxtDiagnostics({
  diagnostics,
  records,
  warnings,
  compact = false,
}: {
  diagnostics?: DnsDiagnostic[] | null;
  records?: DnsRecord[] | null;
  warnings?: string[] | null;
  compact?: boolean;
}) {
  const safeDiagnostics = asDnsDiagnostics(diagnostics);
  const spfDiagnostics = getDnsSpfDiagnostics(safeDiagnostics);
  const spfWarnings = asDnsStrings(warnings).filter((warning) => warning.toLowerCase().includes('spf'));
  const groups = [
    ['DKIM', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'dkim')],
    ['DMARC', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'dmarc')],
    ['Microsoft 365 verification', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'microsoft_365_verification')],
    ['Google verification', safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'google_verification')],
    ["ACME / Let's Encrypt", safeDiagnostics.filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'acme_challenge')],
  ] as const;
  return (
    <div className="min-w-0 space-y-4">
      {spfDiagnostics.map((diagnostic, index) => (
        <DnsSpfExplanation
          key={`${String(diagnostic.value || 'spf')}-${index}`}
          compact={compact}
          diagnostic={diagnostic}
          records={records}
          warnings={spfWarnings}
        />
      ))}
      {!compact && groups.map(([title, groupDiagnostics]) => (
        <div key={title} className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/60 p-4">
          <h4 className="text-sm font-semibold text-zinc-100">{title}</h4>
          <div className="mt-3 min-w-0">
            <DnsDiagnosticList diagnostics={groupDiagnostics} />
          </div>
        </div>
      ))}
    </div>
  );
}
function DnsSpfExplanation({
  diagnostic,
  records,
  warnings,
  compact,
}: {
  diagnostic: DnsDiagnostic;
  records?: DnsRecord[] | null;
  warnings?: string[] | null;
  compact: boolean;
}) {
  const spfValue = typeof diagnostic.value === 'string' ? diagnostic.value : '';
  const mechanisms = getDnsSpfMechanisms(diagnostic);
  const ttl = getDnsSpfTtl(records, spfValue);
  const visibleMechanisms = compact ? mechanisms.slice(0, 8) : mechanisms;
  const hiddenCount = Math.max(0, mechanisms.length - visibleMechanisms.length);
  const parserDetails = [
    ['Lookup count estimate', formatUnknown(diagnostic.lookupCountEstimate)],
    ['Include mechanisms', asDnsStrings(diagnostic.include as string[] | null | undefined).join(', ') || null],
    ['Redirect', typeof diagnostic.redirect === 'string' ? diagnostic.redirect : null],
    ['All mechanism', typeof diagnostic.all === 'string' ? diagnostic.all : null],
  ].filter((detail): detail is [string, string] => Boolean(detail[1]));
  return (
    <article className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/60 p-4">
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h4 className="text-sm font-semibold text-zinc-100">SPF record</h4>
          {spfValue && !compact && (
            <p className="mt-2 break-words font-mono text-xs leading-5 text-zinc-400 [overflow-wrap:anywhere]">
              {spfValue}
            </p>
          )}
        </div>
        {ttl !== null && (
          <span className="w-fit rounded-full border border-emerald-400/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-200">
            DNS TTL: {formatDnsTtlShort(ttl)}
          </span>
        )}
      </div>
      {ttl === null && (
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Resolver cache lifetime was not included with this TXT answer.
        </p>
      )}
      {ttl !== null && !compact && (
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Resolvers may cache this TXT answer for up to {formatDnsTtlShort(ttl)}.
        </p>
      )}
      <div className="mt-4 min-w-0 space-y-2">
        {visibleMechanisms.length > 0 ? visibleMechanisms.map((mechanism, index) => (
          <DnsSpfMechanismRow
            key={`${mechanism.token || 'spf-token'}-${index}`}
            defaultDomain={typeof diagnostic.queryName === 'string' ? diagnostic.queryName : null}
            mechanism={mechanism}
            isFirst={index === 0}
          />
        )) : (
          <p className="text-sm text-zinc-400">No SPF mechanisms were parsed from this record.</p>
        )}
      </div>
      {hiddenCount > 0 && (
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          {hiddenCount} more SPF {hiddenCount === 1 ? 'rule is' : 'rules are'} shown in Advanced view.
        </p>
      )}
      {!compact && warnings && warnings.length > 0 && (
        <div className="mt-4 rounded-xl border border-amber-300/25 bg-amber-400/10 p-3">
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-100">SPF warnings</p>
          <div className="mt-2">
            <DnsStringList values={warnings} />
          </div>
        </div>
      )}
      {!compact && parserDetails.length > 0 && (
        <dl className="mt-4 grid min-w-0 gap-3 md:grid-cols-2">
          {parserDetails.map(([label, value]) => (
            <DnsDetailItem key={label} label={label} value={value} mono={label !== 'Lookup count estimate'} />
          ))}
        </dl>
      )}
    </article>
  );
}
function DnsSpfMechanismRow({
  mechanism,
  defaultDomain,
  isFirst,
}: {
  mechanism: DnsSpfMechanism;
  defaultDomain: string | null;
  isFirst: boolean;
}) {
  const warning = getDnsSpfMechanismWarning(mechanism);
  return (
    <div className={`min-w-0 rounded-xl border p-3 ${
      warning
        ? 'border-amber-300/30 bg-amber-400/10'
        : 'border-white/10 bg-zinc-900/70'
    }`}>
      <div className="grid min-w-0 gap-2 lg:grid-cols-[minmax(0,1fr)_minmax(180px,0.38fr)] lg:items-start">
        <div className="min-w-0">
          <p className="break-words text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere]">
            {describeDnsSpfMechanism(mechanism, defaultDomain, isFirst)}
          </p>
          {warning && (
            <p className="mt-1 break-words text-xs font-semibold leading-5 text-amber-100 [overflow-wrap:anywhere]">
              {warning}
            </p>
          )}
        </div>
        <code className="min-w-0 break-words rounded-lg border border-white/10 bg-zinc-950 px-2 py-1 font-mono text-xs leading-5 text-zinc-400 [overflow-wrap:anywhere]">
          {mechanism.token || '-'}
        </code>
      </div>
    </div>
  );
}
