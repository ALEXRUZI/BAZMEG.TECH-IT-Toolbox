import { useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { CommandBlock } from '../../components/CommandBlock';
import { Field, Label, Panel, ResultItem, inputClass, FieldInput, FieldSelect } from '../../components/Panel';
import { HttpHeaderExportDetailRow, HttpHeaderExportItem, HttpHeaderExportSection, ResultImageCapture, ResultImageCopyControls, ResultImageHeader, TlsResultSection, useResultImageClipboard } from '../../components/ResultImageExport';
import { fetchHttpHeaderCheck } from './httpHeaderApi';
import { formatHttpHeaderProtocolLabel, formatHttpHeaderRedirectStatus, formatMilliseconds, formatSeconds, getFiniteSeconds, getHttpHeaderInputPortSummary, getHttpStatusBadgeClass, getHttpStatusStandardText, getPublicHttpHeaderResult, httpHeaderFindingClass, httpHeaderProtocolModeLabels, httpStatusFamilies } from './httpHeaderHelpers';
import type { HttpStatusFamilyKey } from './httpHeaderHelpers';
import type { HttpHeaderCheck, HttpHeaderCheckErrorResponse, HttpHeaderCheckSuccess, HttpHeaderCspPrivateIpReference, HttpHeaderEntry, HttpHeaderFinding, HttpHeaderInteresting, HttpHeaderProtocolMode, HttpHeaderRedirect, HttpHeaderView } from './httpHeaderTypes';
const httpHeaderHttpsPorts = [
  { value: 443, label: '443 - HTTPS' },
  { value: 4443, label: '4443 - HTTPS alternative' },
  { value: 8443, label: '8443 - HTTPS alternative' },
  { value: 8444, label: '8444 - HTTPS alternative' },
  { value: 9443, label: '9443 - HTTPS alternative' },
  { value: 10443, label: '10443 - HTTPS alternative' },
] as const;
const httpHeaderHttpPorts = [
  { value: 80, label: '80 - HTTP' },
  { value: 8000, label: '8000 - HTTP alternative' },
  { value: 8008, label: '8008 - HTTP alternative' },
  { value: 8080, label: '8080 - HTTP alternative' },
  { value: 8081, label: '8081 - HTTP alternative' },
  { value: 8888, label: '8888 - HTTP alternative' },
] as const;
export function HttpHeaderChecker() {
  const [targetInput, setTargetInput] = useState('');
  const [protocolMode, setProtocolMode] = useState<HttpHeaderProtocolMode>('auto');
  const [selectedHttpsPort, setSelectedHttpsPort] = useState(443);
  const [selectedHttpPort, setSelectedHttpPort] = useState(80);
  const [responseView, setResponseView] = useState<HttpHeaderView>('simple');
  const [result, setResult] = useState<HttpHeaderCheckSuccess | null>(null);
  const portHelpId = useId();
  const [error, setError] = useState<HttpHeaderCheckErrorResponse['error'] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const {
    imageRef: httpHeaderImageRef,
    copyImageStatus,
    copyResultImage: copyHttpHeaderResultImage,
    clearCopyImageStatus,
  } = useResultImageClipboard('Copied result image to clipboard.');
  const hasTarget = targetInput.trim().length > 0;
  const portSelectEnabled = protocolMode === 'http' || protocolMode === 'https';
  const selectedPort = protocolMode === 'https' ? selectedHttpsPort : protocolMode === 'http' ? selectedHttpPort : null;
  const portSelectValue = protocolMode === 'https'
    ? String(selectedHttpsPort)
    : protocolMode === 'http'
      ? String(selectedHttpPort)
      : 'standard';
  const portOptions = protocolMode === 'https'
    ? httpHeaderHttpsPorts
    : protocolMode === 'http'
      ? httpHeaderHttpPorts
      : [{
        value: 'standard',
        label: protocolMode === 'both' ? 'HTTP 80 + HTTPS 443' : 'Standard Auto behavior',
      }] as const;
  async function runHttpHeaderCheck() {
    setIsLoading(true);
    setResult(null);
    setError(null);
    clearCopyImageStatus();
    const payload = {
      target: targetInput,
      protocolMode,
      ...(selectedPort !== null ? { port: selectedPort } : {}),
    };
    try {
      const { response, body } = await fetchHttpHeaderCheck(payload);
      if (!response.ok || 'error' in body) {
        setError(!('error' in body) ? {
          code: 'HTTP_HEADER_CHECK_FAILED',
          message: 'HTTP header check failed.',
        } : body.error);
        return;
      }
      setResult(body);
    } catch {
      setError({
        code: 'HTTP_HEADER_CHECK_FAILED',
        message: 'HTTP header check failed.',
      });
    } finally {
      setIsLoading(false);
    }
  }
  return (
    <Panel title="HTTP Header Checker">
      <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0">
          <p className="max-w-4xl text-sm leading-6 text-zinc-300">
            Check public HTTP/HTTPS websites, inspect useful response headers, and trace up to two redirects.
          </p>
          {protocolMode === 'both' && (
            <div className="mt-4 rounded-2xl border border-amber-300/25 bg-amber-400/10 p-4 text-sm leading-6 text-amber-100">
              Both mode runs HTTP and HTTPS separately, so each sub-check can be live or served from this site's cache.
            </div>
          )}
          <div className="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_260px]">
            <Field>
              <Label>Target</Label>
              <FieldInput
                className={inputClass()}
                placeholder="example.com, https://example.com"
                value={targetInput}
                onChange={(event) => setTargetInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' && hasTarget && !isLoading) {
                    void runHttpHeaderCheck();
                  }
                }}
              />
            </Field>
            <Field>
              <Label>Protocol mode</Label>
              <FieldSelect
                className={inputClass()}
                value={protocolMode}
                onChange={(event) => setProtocolMode(event.target.value as HttpHeaderProtocolMode)}
              >
                {(Object.keys(httpHeaderProtocolModeLabels) as HttpHeaderProtocolMode[]).map((mode) => (
                  <option key={mode} value={mode}>
                    {httpHeaderProtocolModeLabels[mode]}
                  </option>
                ))}
              </FieldSelect>
            </Field>
          </div>
          <details className="mt-4 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
            <summary className="cursor-pointer text-sm font-semibold text-zinc-200">Advanced options</summary>
            <div className="mt-4 grid gap-4 md:grid-cols-[260px_minmax(0,1fr)]">
              <Field>
                <Label>Port</Label>
                <FieldSelect
                  aria-describedby={portHelpId}
                  className={inputClass(false, !portSelectEnabled)}
                  value={portSelectValue}
                  disabled={!portSelectEnabled}
                  onChange={(event) => {
                    if (!portSelectEnabled) {
                      return;
                    }
                    const nextPort = Number(event.target.value);
                    if (protocolMode === 'https') {
                      setSelectedHttpsPort(nextPort);
                    } else {
                      setSelectedHttpPort(nextPort);
                    }
                  }}
                >
                  {portOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </FieldSelect>
              </Field>
              <p id={portHelpId} className="self-end text-sm leading-6 text-zinc-400">
                Advanced port selection only applies to HTTP only and HTTPS only modes. Auto and Both mode always use standard ports.
              </p>
            </div>
          </details>
          <div className="mt-5">
            <button
              className="rounded-xl border border-emerald-500/35 bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition hover:border-emerald-300 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800 disabled:text-zinc-500"
              type="button"
              onClick={() => void runHttpHeaderCheck()}
              disabled={!hasTarget || isLoading}
              aria-busy={isLoading}
            >
              {isLoading ? 'Checking...' : 'Check headers'}
            </button>
          </div>
          {result && <HttpHeaderCacheStatusNotice result={result} />}
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
          {result && (
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <ResultImageCopyControls
                status={copyImageStatus}
                onCopy={() => void copyHttpHeaderResultImage()}
              />
            </div>
          )}
          {error && <HttpHeaderErrorBox error={error} />}
          {result && (
            <div className="mt-6 min-w-0">
              {responseView === 'simple' && <HttpHeaderSimpleView result={result} />}
              {responseView === 'advanced' && <HttpHeaderAdvancedView result={result} />}
              {responseView === 'raw' && <CommandBlock scrollInside>{JSON.stringify(getPublicHttpHeaderResult(result), null, 2)}</CommandBlock>}
            </div>
          )}
          {result && (
            <ResultImageCapture captureRef={httpHeaderImageRef}>
              <HttpHeaderResultImageExport result={result} />
            </ResultImageCapture>
          )}
        </div>
        <HttpStatusHelper />
      </div>
    </Panel>
  );
}
function HttpHeaderResultImageExport({ result }: { result: HttpHeaderCheckSuccess }) {
  return (
    <div className="min-w-0 bg-[#0f1117] text-zinc-100">
      <ResultImageHeader title="HTTP Header Checker" />
      <div className="mt-6 min-w-0 space-y-5">
        <HttpHeaderExportSection title="Input Summary">
          <div className="grid min-w-0 grid-cols-2 gap-3">
            <HttpHeaderExportItem label="User input">{result.input.original}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Protocol mode">{httpHeaderProtocolModeLabels[result.input.protocolMode]}</HttpHeaderExportItem>
          </div>
        </HttpHeaderExportSection>
        <HttpHeaderExportSection title="Checker results">
          <div className="min-w-0 space-y-4">
            {result.checks.map((check, index) => (
              <article key={`${check.protocol}-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
                <h5 className="min-w-0 text-base font-semibold text-zinc-50">
                  {formatHttpHeaderProtocolLabel(check.protocol)} check
                </h5>
                <dl className="mt-4 min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
                  <HttpHeaderExportDetailRow label="Start URL">{check.startUrl}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Final status">
                    <HttpHeaderExportStatusBadge status={check.status} statusText={check.statusText} />
                  </HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Final URL">{check.finalUrl || check.finalCheckedUrl || '-'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Duration">{check.cached ? '0 ms' : formatMilliseconds(check.durationMs)}</HttpHeaderExportDetailRow>
                </dl>
              </article>
            ))}
          </div>
        </HttpHeaderExportSection>
        <HttpHeaderExportSection title="Redirect chain">
          <div className="min-w-0 space-y-4">
            {result.checks.map((check, index) => (
              <article key={`${check.protocol}-redirect-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
                <h5 className="min-w-0 text-base font-semibold text-zinc-50">
                  {formatHttpHeaderProtocolLabel(check.protocol)} redirect path
                </h5>
                <div className="mt-4 min-w-0">
                  <HttpHeaderRedirectChainView check={check} />
                </div>
              </article>
            ))}
          </div>
        </HttpHeaderExportSection>
      </div>
    </div>
  );
}
function HttpHeaderExportStatusBadge({ status, statusText }: { status: number | null; statusText: string | null }) {
  if (!status) {
    return <span>Unavailable</span>;
  }
  const meaning = getHttpStatusStandardText(status) || statusText || 'Status';
  return (
    <span className={`inline-flex whitespace-nowrap items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-semibold ${getHttpStatusBadgeClass(status)}`}>
      <span className="font-mono">{status}</span>
      <span>{meaning}</span>
    </span>
  );
}
function HttpHeaderRedirectChainView({ check }: { check: HttpHeaderCheck }) {
  const redirects = check.redirects || [];
  const firstUrl = redirects[0]?.from || check.chainDisplay || check.finalUrl || check.startUrl;
  if (redirects.length === 0) {
    return (
      <div className="min-w-0">
        <HttpHeaderRedirectStep index={1} value={firstUrl} />
      </div>
    );
  }
  return (
    <div className="min-w-0 space-y-2">
      <HttpHeaderRedirectStep index={1} value={firstUrl} />
      {redirects.map((redirect, index) => (
        <div key={`${redirect.from}-${redirect.to}-${index}`} className="min-w-0">
          <div className="ml-6 border-l border-emerald-400/25 py-2 pl-4">
            <p className="font-mono text-sm font-semibold leading-6 text-emerald-100">
              {formatHttpHeaderRedirectStatus(redirect)}
            </p>
            <p className="font-mono text-lg leading-7 text-emerald-300">↓</p>
          </div>
          {redirect.to === 'X'
            ? <HttpHeaderBlockedRedirectStop />
            : <HttpHeaderRedirectStep index={index + 2} value={redirect.to} />}
        </div>
      ))}
    </div>
  );
}
function HttpHeaderRedirectStep({ index, value }: { index: number; value: string }) {
  return (
    <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] gap-3 rounded-xl border border-white/10 bg-zinc-900/80 px-4 py-3 font-mono text-sm leading-6 text-zinc-100">
      <span className="shrink-0 font-semibold text-emerald-300">{index}.</span>
      <span className="min-w-0 break-words [overflow-wrap:anywhere]">{value}</span>
    </div>
  );
}
function HttpHeaderBlockedRedirectStop() {
  return (
    <div className="inline-flex max-w-full items-center gap-2 rounded-xl border border-red-300/35 bg-red-500/10 px-4 py-3 font-mono text-sm font-semibold leading-6 text-red-100">
      <span className="shrink-0 text-red-200">X</span>
      <span>Blocked</span>
    </div>
  );
}
function HttpHeaderErrorBox({ error }: { error: HttpHeaderCheckErrorResponse['error'] }) {
  const messages: Record<string, string> = {
    IP_NOT_ALLOWED: 'IP addresses are not allowed. Enter a public domain name instead.',
    LOCAL_HOSTNAME_NOT_ALLOWED: 'Local/internal hostnames are not allowed. This tool only checks public websites.',
    UNSUPPORTED_PROTOCOL: 'Unsupported protocol. Only HTTP and HTTPS URLs are supported.',
    INVALID_PORT: 'Port is not supported. Use the Advanced port dropdown with a supported HTTP/HTTPS port.',
    BLOCKED_TARGET: 'Target resolved to a blocked/private/internal address.',
    BLOCKED_REDIRECT: 'Redirect target is blocked because it points to a private/internal/unsupported address.',
    RATE_LIMITED: 'Rate limit reached. Too many HTTP header checks were requested recently. Try again later.',
  };
  return (
    <div className="mt-5 rounded-2xl border border-red-300/35 bg-red-950/40 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Error</p>
      <p className="mt-2 text-sm leading-6 text-red-50">{messages[error.code] || error.message}</p>
    </div>
  );
}
function HttpHeaderSimpleView({ result }: { result: HttpHeaderCheckSuccess }) {
  const importantFindings = result.checks.flatMap((check) => check.findings).filter((finding) => finding.severity !== 'info');
  return (
    <div className="min-w-0 space-y-5">
      <HttpHeaderInputSummary result={result} />
      {result.checks.map((check, index) => (
        <TlsResultSection key={`${check.protocol}-${index}`} title="Checker results">
          <HttpHeaderCheckSummary check={check} />
        </TlsResultSection>
      ))}
      <TlsResultSection title="Security findings">
        <HttpHeaderFindingList findings={importantFindings} />
      </TlsResultSection>
    </div>
  );
}
function HttpHeaderAdvancedView({ result }: { result: HttpHeaderCheckSuccess }) {
  return (
    <div className="min-w-0 space-y-5">
      <HttpHeaderInputSummary result={result} />
      {result.checks.map((check, index) => (
        <TlsResultSection key={`${check.protocol}-${index}`} title="Checker results">
          <div className="space-y-5">
            <HttpHeaderCheckSummary check={check} />
            <HttpHeaderFindingList findings={check.findings} />
            <HttpHeaderInterestingGroups headers={check.interestingHeaders} />
            <HttpHeaderCspPrivateIpReferences findings={check.findings} />
            <HttpHeaderRawHeaders headers={check.headers} />
          </div>
        </TlsResultSection>
      ))}
    </div>
  );
}
function HttpHeaderInputSummary({ result }: { result: HttpHeaderCheckSuccess }) {
  const portSummary = getHttpHeaderInputPortSummary(result);
  return (
    <TlsResultSection title="Input summary">
      <div className="grid gap-3 md:grid-cols-3">
        <ResultItem label="User input" value={result.input.original} />
        <ResultItem label="Protocol mode" value={httpHeaderProtocolModeLabels[result.input.protocolMode]} />
        <ResultItem label={portSummary.label} value={portSummary.value} />
      </div>
    </TlsResultSection>
  );
}
function HttpHeaderCacheStatusNotice({ result }: { result: HttpHeaderCheckSuccess }) {
  const isBothMode = result.input.protocolMode === 'both';
  const primaryCheck = result.checks[0];
  return (
    <aside className="mt-4 min-w-0 rounded-2xl border border-emerald-400/25 bg-emerald-500/10 p-4 text-sm text-emerald-50">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-200">Cache status</p>
          {!isBothMode && primaryCheck && (
            <p className="mt-1 font-semibold text-emerald-50">
              {primaryCheck.cached ? 'Served from this site\'s cache' : 'Live HTTP header check'}
            </p>
          )}
          {isBothMode && (
            <p className="mt-1 font-semibold text-emerald-50">HTTP cache status by protocol</p>
          )}
        </div>
        {!isBothMode && primaryCheck && (
          <HttpHeaderCacheDetails check={primaryCheck} fallbackTtlSeconds={result.cache.ttlSeconds} />
        )}
      </div>
      {isBothMode && (
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          {result.checks.map((check, index) => (
            <section
              key={`${check.protocol}-${index}`}
              className="min-w-0 border-t border-emerald-200/20 pt-3 lg:border-l lg:border-t-0 lg:pl-4 lg:pt-0 lg:first:border-l-0 lg:first:pl-0"
            >
              <p className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200">
                {formatHttpHeaderProtocolLabel(check.protocol)}
              </p>
              <p className="mt-1 font-semibold text-emerald-50">
                {check.cached ? 'Served from this site\'s cache' : 'Live HTTP header check'}
              </p>
              <HttpHeaderCacheDetails check={check} fallbackTtlSeconds={result.cache.ttlSeconds} className="mt-3" />
            </section>
          ))}
        </div>
      )}
      <p className="mt-3 text-xs leading-5 text-emerald-100/85">
        Results may be served from this site's short cache. Cached checks do not consume your request budget.
      </p>
    </aside>
  );
}
function HttpHeaderCacheDetails({
  check,
  fallbackTtlSeconds,
  className = '',
}: {
  check: HttpHeaderCheck;
  fallbackTtlSeconds: number;
  className?: string;
}) {
  const ttlSeconds = getFiniteSeconds(check.cacheTtlSeconds) ?? getFiniteSeconds(fallbackTtlSeconds);
  const ageSeconds = getFiniteSeconds(check.cacheAgeSeconds) ?? (check.cached ? null : 0);
  const expiresInSeconds = getFiniteSeconds(check.cacheExpiresInSeconds) ?? (!check.cached ? ttlSeconds : null);
  const cacheDetails = [
    ['Data served from this site\'s cache', check.cached ? 'Yes' : 'No'],
    ['Cache age', formatSeconds(ageSeconds)],
    ['Expires in', formatSeconds(expiresInSeconds)],
    ['Cache TTL', formatSeconds(ttlSeconds)],
  ].filter((detail): detail is [string, string] => Boolean(detail[1]));
  return (
    <dl className={`grid min-w-0 gap-x-4 gap-y-2 sm:grid-cols-2 ${className}`}>
      {cacheDetails.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200/80">{label}</dt>
          <dd className="mt-0.5 break-words font-mono text-sm text-emerald-50 [overflow-wrap:anywhere]">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
function HttpHeaderCheckSummary({ check }: { check: HttpHeaderCheck }) {
  return (
    <div className="min-w-0 space-y-4">
      <dl className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
        <HttpHeaderDetailRow label="Start URL" valueClassName="break-words [overflow-wrap:anywhere] md:[overflow-wrap:break-word]">
          {check.startUrl}
        </HttpHeaderDetailRow>
        <HttpHeaderDetailRow label="Final status">
          <HttpStatusResultBadge status={check.status} statusText={check.statusText} />
        </HttpHeaderDetailRow>
        <HttpHeaderDetailRow label="Final URL" valueClassName="break-words [overflow-wrap:anywhere] md:[overflow-wrap:break-word]">
          {check.finalUrl || check.finalCheckedUrl || '-'}
        </HttpHeaderDetailRow>
        <HttpHeaderDetailRow label="Duration">
          {check.cached ? '0 ms' : formatMilliseconds(check.durationMs)}
        </HttpHeaderDetailRow>
      </dl>
      <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Redirect chain</p>
        <HttpHeaderRedirectChain check={check} />
      </div>
    </div>
  );
}
function HttpHeaderDetailRow({
  label,
  children,
  valueClassName = '',
}: {
  label: string;
  children: ReactNode;
  valueClassName?: string;
}) {
  return (
    <div className="min-w-0 border-b border-white/10 py-3 first:pt-0 last:border-b-0 last:pb-0">
      <dt className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">{label}</dt>
      <dd className={`mt-1 min-w-0 font-mono text-sm leading-6 text-zinc-100 ${valueClassName}`}>
        {children || '-'}
      </dd>
    </div>
  );
}
function HttpHeaderRedirectChain({ check }: { check: HttpHeaderCheck }) {
  return (
    <div className="mt-3">
      <HttpHeaderRedirectChainView check={check} />
    </div>
  );
}
function HttpStatusResultBadge({ status, statusText }: { status: number | null; statusText: string | null }) {
  if (!status) {
    return <span>Unavailable</span>;
  }
  const meaning = getHttpStatusStandardText(status) || statusText || 'Status';
  return (
    <span className={`inline-flex max-w-full flex-wrap items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-semibold ${getHttpStatusBadgeClass(status)}`}>
      <span className="font-mono">{status}</span>
      <span>{meaning}</span>
    </span>
  );
}
function HttpHeaderFindingList({ findings }: { findings: HttpHeaderFinding[] }) {
  if (findings.length === 0) {
    return <p className="text-sm text-zinc-400">No important findings were returned.</p>;
  }
  return (
    <div className="min-w-0 space-y-3">
      {findings.map((finding, index) => (
        <article key={`${finding.code}-${index}`} className={`rounded-xl border p-4 ${httpHeaderFindingClass(finding.severity)}`}>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-current px-2 py-0.5 text-xs font-semibold uppercase tracking-[0.12em]">
              {finding.severity}
            </span>
            <h4 className="text-sm font-semibold">{finding.title}</h4>
          </div>
          <p className="mt-2 text-sm leading-6">{finding.detail}</p>
          <p className="mt-2 text-sm leading-6 opacity-90">{finding.recommendation}</p>
        </article>
      ))}
    </div>
  );
}
function HttpHeaderInterestingGroups({ headers }: { headers: HttpHeaderInteresting[] }) {
  if (headers.length === 0) {
    return <p className="text-sm text-zinc-400">No tracked headers were detected.</p>;
  }
  const categories = [...new Set(headers.map((header) => header.category))];
  return (
    <div className="min-w-0 space-y-4">
      {categories.map((category) => (
        <div key={category} className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <h4 className="text-sm font-semibold text-zinc-100">{category}</h4>
          <div className="mt-3 grid min-w-0 gap-3">
            {headers.filter((header) => header.category === category).map((header) => (
              <div key={header.name} className="min-w-0 rounded-xl border border-white/10 bg-zinc-900/70 p-3">
                <p className="font-mono text-sm font-semibold text-emerald-200">{header.name}</p>
                <p className="mt-1 text-sm leading-6 text-zinc-300">{header.explanation}</p>
                <p className="mt-2 break-words font-mono text-xs leading-5 text-zinc-100 [overflow-wrap:anywhere]">
                  {header.values.join('\n')}
                </p>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
function HttpHeaderCspPrivateIpReferences({ findings }: { findings: HttpHeaderFinding[] }) {
  const finding = findings.find((entry) => entry.code === 'CSP_EXPOSES_PRIVATE_IP');
  const references = finding?.metadata?.references?.filter((reference) => reference.privateIps?.length > 0) || [];
  const privateIps = finding?.metadata?.privateIps || [];
  return (
    <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <h4 className="text-sm font-semibold uppercase tracking-[0.16em] text-emerald-200">
        CSP private/internal IP references
      </h4>
      {references.length === 0 && privateIps.length === 0 ? (
        <p className="mt-3 text-sm text-zinc-400">N/A</p>
      ) : (
        <div className="mt-3 space-y-3">
          {privateIps.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {privateIps.map((ip) => (
                <span
                  key={ip}
                  className="rounded-full border border-amber-300/35 bg-amber-400/10 px-3 py-1 font-mono text-xs font-semibold text-amber-100"
                >
                  {ip}
                </span>
              ))}
            </div>
          )}
          {references.map((reference, index) => (
            <article key={`${reference.header}-${index}`} className="min-w-0 rounded-xl border border-white/10 bg-zinc-900/70 p-3">
              <p className="font-mono text-sm font-semibold text-emerald-200">{reference.header}</p>
              <p className="mt-2 break-words font-mono text-xs leading-5 text-zinc-100 [overflow-wrap:anywhere]">
                {reference.value}
              </p>
              <p className="mt-2 text-xs leading-5 text-zinc-300">
                Found: {reference.privateIps.join(', ')}
              </p>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
function HttpHeaderRawHeaders({ headers }: { headers: HttpHeaderEntry[] }) {
  const raw = headers.map((header) => `${header.name}: ${header.value}`).join('\n');
  return (
    <div>
      <h4 className="text-sm font-semibold uppercase tracking-[0.16em] text-emerald-200">Raw headers</h4>
      <CommandBlock scrollInside>{raw || '-'}</CommandBlock>
    </div>
  );
}
function HttpStatusHelper() {
  const [expandedFamily, setExpandedFamily] = useState<HttpStatusFamilyKey | null>(null);
  const activeFamily = httpStatusFamilies.find((family) => family.key === expandedFamily) || null;
  return (
    <aside className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/80 p-4 shadow-lg shadow-black/25 xl:sticky xl:top-6 xl:self-start">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-200">HTTP status codes</p>
        <h3 className="mt-1 text-lg font-semibold text-zinc-50">Response families</h3>
      </div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
        {httpStatusFamilies.map((family) => (
          <button
            key={family.key}
            className={`flex w-full items-center justify-between gap-3 rounded-xl border px-3 py-3 text-left text-sm transition ${family.buttonClass} ${
              expandedFamily === family.key ? 'ring-2 ring-white/25' : ''
            }`}
            type="button"
            aria-expanded={expandedFamily === family.key}
            onClick={() => setExpandedFamily((current) => current === family.key ? null : family.key)}
          >
            <span className="font-mono text-base font-bold">{family.key}</span>
            <span className="font-semibold">{family.label}</span>
          </button>
        ))}
      </div>
      {activeFamily && (
        <div className="mt-4 space-y-2 border-t border-white/10 pt-4">
          {activeFamily.codes.map(({ code, label, detail }) => (
            <div key={code} className="rounded-xl border border-white/10 bg-zinc-900/85 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-full border px-2.5 py-1 font-mono text-xs font-semibold ${getHttpStatusBadgeClass(code)}`}>
                  {code}
                </span>
                <span className="text-sm font-semibold text-zinc-50">{label}</span>
              </div>
              <p className="mt-2 text-xs leading-5 text-zinc-300">{detail}</p>
            </div>
          ))}
        </div>
      )}
    </aside>
  );
}
