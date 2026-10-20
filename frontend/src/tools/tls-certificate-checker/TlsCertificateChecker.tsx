import { useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Field, Label, Panel, ResultBlock, ResultItem, inputClass, FieldInput, FieldSelect, FieldDescription } from '../../components/Panel';
import { DnsStringList, HttpHeaderExportDetailRow, HttpHeaderExportItem, HttpHeaderExportSection, ResultImageCapture, ResultImageCopyControls, ResultImageHeader, TlsResultSection, useResultImageClipboard } from '../../components/ResultImageExport';
import { fetchTlsCertificateCheck } from './tlsApi';
import { formatDistinguishedName, formatOptionalNumber, getCertificateTypeConfidenceLabel, getTlsExpirationPresentation, getTlsIssuerCertificateTitle, getTlsIssuerChain, getTlsServerProvidedCertificateCount, getTlsSummaryChecks, normalizeTlsHostInput, parseSubjectAltNames, tlsIssuerProvenanceNote } from './tlsHelpers';
import type { TlsCertificateDetail, TlsCertificateTypeConfidence, TlsCertificateValidationType, TlsCheckErrorResponse, TlsCheckStatus, TlsCheckSuccess, TlsIssuerChainEntry } from './tlsTypes';
const tlsPortOptions = [
  { value: 443, label: '443 - HTTPS' },
  { value: 4443, label: '4443 - HTTPS alternate' },
  { value: 7443, label: '7443 - HTTPS alternate' },
  { value: 8443, label: '8443 - HTTPS alternate' },
  { value: 9443, label: '9443 - HTTPS alternate' },
  { value: 10443, label: '10443 - HTTPS alternate / appliance HTTPS' },
] as const;
const tlsCertificateTypeTooltip =
  'Best signal is the certificate policy OID. Issuer name alone is only a hint.';
export function TlsCertificateChecker() {
  const tlsHostExample = 'google.com';
  const [hostInput, setHostInput] = useState('');
  const [selectedPort, setSelectedPort] = useState(443);
  const [isHostFocused, setIsHostFocused] = useState(false);
  const [result, setResult] = useState<TlsCheckSuccess | null>(null);
  const [error, setError] = useState<TlsCheckErrorResponse['error'] | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const {
    imageRef: tlsImageRef,
    copyImageStatus,
    copyResultImage: copyTlsResultImage,
    clearCopyImageStatus,
  } = useResultImageClipboard('Copied TLS certificate result image to clipboard.');
  const hasHost = hostInput.trim().length > 0;
  async function checkCertificate() {
    const normalizedHost = normalizeTlsHostInput(hostInput);
    setHostInput(normalizedHost);
    setIsLoading(true);
    setResult(null);
    setError(null);
    clearCopyImageStatus();
    try {
      const { response, body } = await fetchTlsCertificateCheck(normalizedHost, selectedPort);
      if (!response.ok || !body.ok) {
        setError(body.ok ? {
          code: 'TLS_CHECK_FAILED',
          message: 'Certificate check failed.',
        } : body.error);
        return;
      }
      setResult(body);
    } catch {
      setError({
        code: 'TLS_CHECK_FAILED',
        message: 'Certificate check failed.',
      });
    } finally {
      setIsLoading(false);
    }
  }
  return (
    <Panel title="TLS/SSL certificate checker">
      <p className="max-w-4xl text-sm leading-6 text-zinc-300">
        Check the public certificate and TLS settings for an HTTPS endpoint.
      </p>
      <div className="mt-5 grid gap-4 md:grid-cols-[minmax(0,1fr)_260px_auto]">
        <Field>
          <Label>Hostname</Label>
          <div className="relative">
            {!hostInput && !isHostFocused && (
              <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-sm text-zinc-500">
                {tlsHostExample}
              </span>
            )}
            <FieldInput
              aria-label="Hostname"
              className={inputClass()}
              value={hostInput}
              onBlur={() => {
                setIsHostFocused(false);
                setHostInput((value) => normalizeTlsHostInput(value));
              }}
              onChange={(event) => setHostInput(event.target.value)}
              onFocus={() => setIsHostFocused(true)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && hasHost && !isLoading) {
                  void checkCertificate();
                }
              }}
            />
          </div>
        </Field>
        <Field description="Only common direct-TLS HTTPS ports are supported.">
          <Label>Port</Label>
          <FieldSelect
            className={inputClass()}
            value={selectedPort}
            onChange={(event) => setSelectedPort(Number(event.target.value))}
          >
            {tlsPortOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </FieldSelect>
          <FieldDescription />
        </Field>
        <div className="flex items-end">
          <button
            className="w-full rounded-xl border border-emerald-500/35 bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 transition hover:border-emerald-300 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:border-zinc-700 disabled:bg-zinc-800 disabled:text-zinc-500 md:w-auto"
            type="button"
            onClick={() => void checkCertificate()}
            disabled={!hasHost || isLoading}
            aria-busy={isLoading}
          >
            {isLoading ? 'Checking...' : 'Check certificate'}
          </button>
        </div>
      </div>
      {error && (
        <div className="mt-5 rounded-2xl border border-red-300/35 bg-red-950/40 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Error code</p>
          <p className="mt-1 font-mono text-sm text-red-100">{error.code}</p>
          <p className="mt-4 text-xs font-semibold uppercase tracking-[0.16em] text-red-200">Message</p>
          <p className="mt-1 text-sm leading-6 text-red-50">{error.message}</p>
        </div>
      )}
      {result && (
        <div className="mt-6 space-y-5">
          <ResultImageCopyControls
            status={copyImageStatus}
            onCopy={() => void copyTlsResultImage()}
          />
          <TlsResultSection title="Result summary">
            <div className="space-y-3">
              <TlsCertificateTypeBadge
                certificateType={result.certificateType}
                confidence={result.certificateTypeConfidence}
                reason={result.certificateTypeReason}
              />
              {getTlsSummaryChecks(result).map((check) => (
                <TlsCheckRow key={check.id} check={check} />
              ))}
            </div>
          </TlsResultSection>
          <TlsResultSection title="TLS status">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <ResultItem label="Host" value={result.host} />
              <ResultItem label="Port" value={String(result.port)} />
              <ResultItem label="Authorized" value={result.tls.authorized ? 'Yes' : 'No'} />
              <ResultItem label="Authorization error" value={result.tls.authorizationError} />
              <ResultItem label="Protocol" value={result.tls.protocol} />
              <ResultItem label="Cipher" value={result.tls.cipher} />
            </div>
          </TlsResultSection>
          <TlsResultSection title="DNS resolution">
            <TlsListBlock values={result.resolvedAddresses} />
          </TlsResultSection>
          <TlsResultSection title="Server certificate">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <ResultItem label="Subject CN" value={result.certificate.subject.CN} />
              <ResultItem label="Issuer CN" value={result.certificate.issuer.CN} />
              <ResultItem label="Issuer O" value={result.certificate.issuer.O} />
              <ResultItem label="Valid from" value={result.certificate.validFrom} />
              <ResultItem label="Valid to" value={result.certificate.validTo} />
              <ResultItem label="Days remaining" value={formatOptionalNumber(result.certificate.daysRemaining)} />
              <ResultItem label="Serial number" value={result.certificate.serialNumber} />
              <ResultItem label="SHA256 fingerprint" value={result.certificate.fingerprint256} />
            </div>
            <div className="mt-3">
              <TlsListBlock values={parseSubjectAltNames(result.certificate.subjectAltName)} fallback={result.certificate.subjectAltName} />
            </div>
          </TlsResultSection>
          <TlsCertificateChain chain={result.chain} />
          <p className="text-sm leading-6 text-zinc-300">{result.issuerChainNote || tlsIssuerProvenanceNote}</p>
          {result.warnings.length > 0 && (
            <TlsResultSection title="Warnings">
              <TlsListBlock values={result.warnings} />
            </TlsResultSection>
          )}
          <ResultImageCapture captureRef={tlsImageRef}>
            <TlsResultImageExport result={result} />
          </ResultImageCapture>
        </div>
      )}
    </Panel>
  );
}
function TlsResultImageExport({ result }: { result: TlsCheckSuccess }) {
  const expiration = getTlsExpirationPresentation(result.certificate);
  const issuerChain = getTlsIssuerChain(result);
  const serverProvidedCertificateCount = getTlsServerProvidedCertificateCount(result);
  const summaryChecks = getTlsSummaryChecks(result, serverProvidedCertificateCount, issuerChain.length)
    .filter((check) => check.id !== 'certificate_expiry');
  const issuerChainNote = result.issuerChainNote || tlsIssuerProvenanceNote;
  return (
    <div className="min-w-0 bg-[#0f1117] text-zinc-100">
      <ResultImageHeader title="TLS/SSL Certificate Checker" />
      <div className="mt-6 min-w-0 space-y-5">
        <HttpHeaderExportSection title="Endpoint summary">
          <div className="grid min-w-0 grid-cols-2 gap-3">
            <HttpHeaderExportItem label="Host">{result.host}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Port">{String(result.port)}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Protocol">{result.tls.protocol || '-'}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Cipher">{result.tls.cipher || '-'}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Authorized">{result.tls.authorized ? 'Yes' : 'No'}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Certificate type">
              {result.certificateType && result.certificateType !== 'Unknown' ? result.certificateType : 'Unknown / Not detected'}
            </HttpHeaderExportItem>
            <HttpHeaderExportItem label="Server-provided certificates">{serverProvidedCertificateCount ?? 'Unknown'}</HttpHeaderExportItem>
            <HttpHeaderExportItem label="Issuer chain entries shown">{String(issuerChain.length)}</HttpHeaderExportItem>
          </div>
        </HttpHeaderExportSection>
        <HttpHeaderExportSection title="Result summary">
          <div className="min-w-0 space-y-3">
            {summaryChecks.map((check) => (
              <TlsExportCheckRow key={check.id} check={check} />
            ))}
          </div>
        </HttpHeaderExportSection>
        <HttpHeaderExportSection title="Certificate expiration">
          <div className={`min-w-0 rounded-2xl border p-5 ${expiration.className}`}>
            <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <p className="text-xs font-semibold uppercase tracking-[0.16em]">Expiration status</p>
                <p className="mt-2 break-words text-2xl font-semibold text-white [overflow-wrap:anywhere]">
                  {expiration.label}
                </p>
              </div>
              <span className="w-fit rounded-full border border-current px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em]">
                {expiration.badge}
              </span>
            </div>
            <dl className="mt-5 grid min-w-0 gap-3 md:grid-cols-3">
              <HttpHeaderExportItem label="Valid from">{result.certificate.validFrom || '-'}</HttpHeaderExportItem>
              <HttpHeaderExportItem label="Valid until">{result.certificate.validTo || '-'}</HttpHeaderExportItem>
              <HttpHeaderExportItem label="Days remaining">{expiration.daysText}</HttpHeaderExportItem>
            </dl>
          </div>
        </HttpHeaderExportSection>
        <HttpHeaderExportSection title="Issuer chain">
          <div className="min-w-0 space-y-4">
            {issuerChain.length > 0 ? issuerChain.map((entry, index) => (
              <article key={`${entry.fingerprint256 || entry.subject || entry.level}-${index}`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
                <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <h5 className="min-w-0 text-base font-semibold leading-6 text-zinc-50">{getTlsIssuerCertificateTitle(entry, index)}</h5>
                  <TlsIssuerSourceBadge source={entry.source} />
                </div>
                <dl className="mt-4 min-w-0 rounded-2xl border border-white/10 bg-zinc-950/70 p-4">
                  <HttpHeaderExportDetailRow label="Subject">{entry.subject || '-'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Issuer">{entry.issuer || '-'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Valid from">{entry.validFrom || '-'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Valid until">{entry.validTo || '-'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="SHA256 fingerprint">{entry.fingerprint256 || '-'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Signature algorithm">{entry.signatureAlgorithm || 'Unknown / Unavailable'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Public key">{[entry.publicKeyAlgorithm, entry.modulusLength ? `${entry.modulusLength} modulus bits` : null, entry.namedCurve].filter(Boolean).join(' / ') || 'Unknown / Unavailable'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="Self-issued">{entry.selfIssued == null ? 'Unknown' : entry.selfIssued ? 'Yes' : 'No'}</HttpHeaderExportDetailRow>
                  <HttpHeaderExportDetailRow label="CA">{entry.ca == null ? 'Unknown' : entry.ca ? 'Yes' : 'No'}</HttpHeaderExportDetailRow>
                </dl>
              </article>
            )) : (
              <p className="text-sm leading-6 text-zinc-400">No issuer chain entries were returned.</p>
            )}
            {issuerChainNote && (
              <p className="rounded-xl border border-white/10 bg-zinc-950/60 px-4 py-3 text-sm leading-6 text-zinc-300">
                {issuerChainNote}
              </p>
            )}
          </div>
        </HttpHeaderExportSection>
        {result.warnings.length > 0 && (
          <HttpHeaderExportSection title="Warnings">
            <DnsStringList values={result.warnings} />
          </HttpHeaderExportSection>
        )}
      </div>
    </div>
  );
}
function TlsExportCheckRow({ check }: { check: { status: TlsCheckStatus; message: string } }) {
  const statusCopy = {
    pass: { label: 'Pass', className: 'border-emerald-400/35 bg-emerald-500/10 text-emerald-200' },
    warn: { label: 'Warn', className: 'border-amber-300/35 bg-amber-400/10 text-amber-100' },
    fail: { label: 'Fail', className: 'border-red-300/35 bg-red-500/10 text-red-100' },
  }[check.status];
  return (
    <div className={`min-w-0 rounded-xl border p-4 ${statusCopy.className}`}>
      <p className="text-xs font-semibold uppercase tracking-[0.16em]">{statusCopy.label}</p>
      <p className="mt-1 break-words text-sm leading-6 [overflow-wrap:anywhere]">{check.message}</p>
    </div>
  );
}
function TlsIssuerSourceBadge({ source }: { source: TlsIssuerChainEntry['source'] }) {
  const sourceDisplay = {
    peer: {
      label: 'PEER LEAF',
      className: 'border-emerald-400/25 bg-emerald-500/10 text-emerald-200',
    },
    'server-provided': {
      label: 'SERVER PROVIDED',
      className: 'border-emerald-400/25 bg-emerald-500/10 text-emerald-200',
    },
    'local-trust-store': {
      label: 'LOCAL TRUST STORE',
      className: 'border-sky-300/30 bg-sky-400/10 text-sky-100',
    },
    inferred: {
      label: 'ORIGIN UNVERIFIED',
      className: 'border-amber-300/30 bg-amber-400/10 text-amber-100',
    },
    unavailable: {
      label: 'UNAVAILABLE',
      className: 'border-zinc-500/40 bg-zinc-800/60 text-zinc-300',
    },
  }[source];
  return (
    <span className={`min-w-max shrink-0 whitespace-nowrap rounded-full border px-3 py-1 text-xs font-semibold tracking-[0.14em] ${sourceDisplay.className}`}>
      {sourceDisplay.label}
    </span>
  );
}
function TlsCertificateTypeBadge({
  certificateType,
  confidence,
  reason,
}: {
  certificateType?: TlsCertificateValidationType;
  confidence?: TlsCertificateTypeConfidence;
  reason?: string | null;
}) {
  const displayType = certificateType && certificateType !== 'Unknown' ? certificateType : 'Unknown / Not detected';
  const confidenceLabel = getCertificateTypeConfidenceLabel(confidence);
  const badgeText = confidenceLabel && certificateType !== 'Unknown' ? `${displayType} · ${confidenceLabel}` : displayType;
  const tooltipText = [reason, tlsCertificateTypeTooltip].filter(Boolean).join(' ');
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-emerald-400/25 bg-emerald-500/10 p-3 text-emerald-100">
      <span className="text-xs font-semibold uppercase tracking-[0.16em]">Certificate type</span>
      <span className="group relative inline-flex">
        <span
          className="rounded-full border border-emerald-400/35 bg-zinc-950/70 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200 outline-none transition focus:border-emerald-200 focus:ring-2 focus:ring-emerald-400/40"
          tabIndex={0}
          title={tooltipText}
          aria-label={`Certificate type: ${badgeText}. ${tooltipText}`}
        >
          {badgeText}
        </span>
        <span className="pointer-events-none absolute left-0 top-[calc(100%+0.5rem)] z-20 hidden w-72 max-w-[calc(100vw-3rem)] rounded-lg border border-emerald-400/25 bg-zinc-950 px-3 py-2 text-xs normal-case leading-5 tracking-normal text-zinc-200 shadow-xl shadow-black/40 group-hover:block group-focus-within:block">
          {tooltipText}
        </span>
      </span>
    </div>
  );
}
function TlsCheckRow({ check }: { check: { status: TlsCheckStatus; message: string } }) {
  const statusCopy = {
    pass: { icon: '✓', label: 'Pass', className: 'border-emerald-400/35 bg-emerald-500/10 text-emerald-200' },
    warn: { icon: '!', label: 'Warn', className: 'border-amber-300/35 bg-amber-400/10 text-amber-100' },
    fail: { icon: '×', label: 'Fail', className: 'border-red-300/35 bg-red-500/10 text-red-100' },
  }[check.status];
  return (
    <div className={`flex items-start gap-3 rounded-xl border p-3 ${statusCopy.className}`}>
      <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border border-current text-sm font-bold">
        {statusCopy.icon}
      </span>
      <div>
        <p className="text-xs font-semibold uppercase tracking-[0.16em]">{statusCopy.label}</p>
        <p className="mt-1 text-sm leading-6">{check.message}</p>
      </div>
    </div>
  );
}
function TlsCertificateChain({ chain }: { chain: TlsCertificateDetail[] }) {
  if (chain.length === 0) {
    return null;
  }
  return (
    <TlsResultSection title="Certificate chain">
      <div className="space-y-3">
        {chain.map((certificate, index) => (
          <div key={`${certificate.fingerprint256 || certificate.serialNumber || index}-${index}`}>
            <TlsCertificateCard certificate={certificate} index={index} />
            {index < chain.length - 1 && (
              <div className="flex justify-center py-2 text-emerald-300/70" aria-hidden="true">
                ↓
              </div>
            )}
          </div>
        ))}
      </div>
    </TlsResultSection>
  );
}
function TlsCertificateCard({ certificate, index }: { certificate: TlsCertificateDetail; index: number }) {
  const title = index === 0 ? 'Server certificate' : getChainCertificateTitle(certificate, index);
  const expiration = getTlsExpirationPresentation(certificate);
  const keyDetails = [
    certificate.publicKeyAlgorithm,
    certificate.modulusLength ? `${certificate.modulusLength} modulus bits` : null,
    certificate.namedCurve,
  ].filter(Boolean).join(' / ');
  return (
    <article className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h4 className="text-base font-semibold text-zinc-100">{title}</h4>
          <p className="mt-1 text-sm text-zinc-400">{certificate.subject.CN || 'Subject CN unavailable'}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <TlsIssuerSourceBadge source={index === 0 ? 'peer' : 'inferred'} />
          <span className="rounded-full border border-emerald-400/25 bg-emerald-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200">
            {certificate.type}
          </span>
        </div>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        <ResultItem label="Expiration status" value={expiration.badge} />
        <ResultItem label="CA" value={certificate.ca == null ? 'Unknown' : certificate.ca ? 'Yes' : 'No'} />
        <ResultItem label="Self-issued" value={certificate.selfIssued == null ? 'Unknown' : certificate.selfIssued ? 'Yes' : 'No'} />
        <ResultItem label="Subject CN" value={certificate.subject.CN} />
        <ResultItem label="Issuer CN" value={certificate.issuer.CN} />
        <ResultItem label="Issuer O" value={certificate.issuer.O} />
        <ResultItem label="Valid from" value={certificate.validFrom} />
        <ResultItem label="Valid to" value={certificate.validTo} />
        <ResultItem label="Days remaining" value={formatOptionalNumber(certificate.daysRemaining)} />
        <ResultItem label="Serial number" value={certificate.serialNumber} />
        <ResultItem label="Signature algorithm" value={certificate.signatureAlgorithm || 'Unknown / Unavailable'} />
        <ResultItem label="Public key" value={keyDetails || 'Unknown / Unavailable'} />
      </div>
      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <ResultBlock label="SHA256 fingerprint" value={certificate.fingerprint256} />
        <div className="rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Subject Alternative Names</p>
          <div className="mt-3">
            <TlsListBlock values={parseSubjectAltNames(certificate.subjectAltName)} fallback={certificate.subjectAltName} />
          </div>
        </div>
      </div>
    </article>
  );
}
function getChainCertificateTitle(certificate: TlsCertificateDetail, index: number) {
  if (certificate.type === 'self-signed-ca') {
    return 'Self-signed CA certificate (trust unverified)';
  }
  if (certificate.type === 'self-issued') return 'Self-issued certificate';
  if (certificate.type === 'intermediate') {
    return 'Intermediate certificate';
  }
  return `Chain certificate ${index + 1}`;
}
function TlsListBlock({ values, fallback }: { values: string[]; fallback?: string | null }) {
  const displayValues = values.length > 0 ? values : fallback ? [fallback] : [];
  if (displayValues.length === 0) {
    return <p className="text-sm text-zinc-400">-</p>;
  }
  return (
    <details className="rounded-xl border border-white/10 bg-zinc-950/60 p-4" open={displayValues.length <= 8}>
      <summary className="cursor-pointer text-sm font-semibold text-zinc-200">
        {displayValues.length} {displayValues.length === 1 ? 'item' : 'items'}
      </summary>
      <div className="mt-3 max-h-64 space-y-2 overflow-auto pr-2">
        {displayValues.map((value, index) => (
          <div
            key={`${value}-${index}`}
            className="break-words rounded-lg border border-white/10 bg-zinc-950 px-3 py-2 font-mono text-xs leading-5 text-zinc-100"
          >
            {value}
          </div>
        ))}
      </div>
    </details>
  );
}
