import { useEffect, useRef, useState } from 'react';
import type { ReactNode, RefObject } from 'react';
import { toBlob } from 'html-to-image';

type CopyImageStatus = {
  type: 'loading' | 'success' | 'error';
  message: string;
};

const copyImageUnsupportedMessage = 'Could not copy image to clipboard. Your browser may not support image clipboard access.';

export function useResultImageClipboard(successMessage: string) {
  const [copyImageStatus, setCopyImageStatus] = useState<CopyImageStatus | null>(null);
  const imageRef = useRef<HTMLDivElement | null>(null);
  const copyImageStatusTimerRef = useRef<number | null>(null);

  useEffect(() => () => {
    if (copyImageStatusTimerRef.current !== null) {
      window.clearTimeout(copyImageStatusTimerRef.current);
    }
  }, []);

  function clearCopyImageStatusTimer() {
    if (copyImageStatusTimerRef.current !== null) {
      window.clearTimeout(copyImageStatusTimerRef.current);
      copyImageStatusTimerRef.current = null;
    }
  }

  function setTemporaryCopyImageStatus(status: CopyImageStatus) {
    clearCopyImageStatusTimer();
    setCopyImageStatus(status);

    if (status.type !== 'loading') {
      copyImageStatusTimerRef.current = window.setTimeout(() => {
        setCopyImageStatus(null);
        copyImageStatusTimerRef.current = null;
      }, 3200);
    }
  }

  function clearCopyImageStatus() {
    clearCopyImageStatusTimer();
    setCopyImageStatus(null);
  }

  async function copyResultImage() {
    const captureNode = imageRef.current;

    if (!captureNode) {
      return;
    }

    if (!window.isSecureContext || !navigator.clipboard || typeof window.ClipboardItem === 'undefined') {
      setTemporaryCopyImageStatus({
        type: 'error',
        message: copyImageUnsupportedMessage,
      });
      return;
    }

    setTemporaryCopyImageStatus({ type: 'loading', message: 'Copying...' });

    try {
      const blob = await toBlob(captureNode, {
        pixelRatio: 2,
        cacheBust: true,
        backgroundColor: '#0f1117',
      });

      if (!blob) {
        throw new Error('Image rendering returned no data.');
      }

      await navigator.clipboard.write([
        new window.ClipboardItem({ 'image/png': blob }),
      ]);

      setTemporaryCopyImageStatus({
        type: 'success',
        message: successMessage,
      });
    } catch {
      setTemporaryCopyImageStatus({
        type: 'error',
        message: copyImageUnsupportedMessage,
      });
    }
  }

  return {
    imageRef,
    copyImageStatus,
    copyResultImage,
    clearCopyImageStatus,
  };
}

export function ResultImageCopyControls({
  status,
  onCopy,
}: {
  status: CopyImageStatus | null;
  onCopy: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <button
        className="rounded-xl border border-emerald-500/35 bg-zinc-950/80 px-4 py-2 text-sm font-semibold text-emerald-200 transition hover:border-emerald-300 hover:bg-emerald-500/10 disabled:cursor-wait disabled:border-zinc-700 disabled:text-zinc-500"
        type="button"
        onClick={onCopy}
        disabled={status?.type === 'loading'}
        aria-busy={status?.type === 'loading'}
      >
        {status?.type === 'loading' ? 'Copying...' : 'Copy result image'}
      </button>
      {status && (
        <p className={`text-sm leading-6 ${getCopyImageStatusClass(status.type)}`} aria-live="polite">
          {status.message}
        </p>
      )}
    </div>
  );
}

export function ResultImageCapture({
  captureRef,
  children,
}: {
  captureRef: RefObject<HTMLDivElement | null>;
  children: ReactNode;
}) {
  return (
    <div className="pointer-events-none fixed top-0" style={{ left: '-10000px' }} aria-hidden="true">
      <div
        ref={captureRef}
        className="w-[1100px] max-w-[1100px] overflow-hidden rounded-3xl border border-emerald-500/15 bg-[#0f1117] p-8 text-zinc-100 shadow-2xl shadow-black"
      >
        {children}
      </div>
    </div>
  );
}

export function ResultImageHeader({ title }: { title: string }) {
  return (
    <header className="min-w-0 border-b border-white/10 pb-6">
      <div className="min-w-0">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-emerald-200">
          BAZMEG.TECH IT Toolbox
        </p>
        <p className="mt-1 font-mono text-sm text-zinc-400">toolbox.bazmeg.tech</p>
        <h3 className="mt-2 text-3xl font-semibold text-white">{title}</h3>
      </div>
    </header>
  );
}

export function TlsResultSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 max-w-full rounded-2xl border border-emerald-500/15 bg-zinc-900/70 p-4">
      <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-emerald-200">{title}</h3>
      <div className="mt-4 min-w-0">{children}</div>
    </section>
  );
}

export function HttpHeaderExportSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="min-w-0 rounded-2xl border border-emerald-500/15 bg-zinc-900/80 p-5">
      <h4 className="text-sm font-semibold uppercase tracking-[0.16em] text-emerald-200">{title}</h4>
      <div className="mt-4 min-w-0">{children}</div>
    </section>
  );
}

export function HttpHeaderExportDetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 border-b border-white/10 py-3 first:pt-0 last:border-b-0 last:pb-0">
      <dt className="text-xs font-semibold uppercase tracking-[0.16em] text-zinc-500">{label}</dt>
      <dd className="mt-1 min-w-0 break-words font-mono text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere] [word-break:break-word]">
        {children || '-'}
      </dd>
    </div>
  );
}

export function HttpHeaderExportItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 rounded-xl border border-white/10 bg-zinc-950/70 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-zinc-500">{label}</p>
      <div className="mt-2 min-w-0 break-words font-mono text-sm leading-6 text-zinc-100 [overflow-wrap:anywhere] [word-break:break-word]">
        {children || '-'}
      </div>
    </div>
  );
}

export function DnsStringList({ values }: { values?: string[] | null }) {
  const safeValues = Array.isArray(values) ? values.filter((value): value is string => typeof value === 'string') : [];

  if (safeValues.length === 0) {
    return <p className="text-sm text-zinc-400">None.</p>;
  }

  return (
    <ul className="min-w-0 space-y-2 text-sm leading-6 text-zinc-300">
      {safeValues.map((value, index) => (
        <li key={`${value}-${index}`} className="min-w-0 break-words rounded-xl border border-white/10 bg-zinc-950/60 px-3 py-2 [overflow-wrap:anywhere]">
          {value}
        </li>
      ))}
    </ul>
  );
}

function getCopyImageStatusClass(type: CopyImageStatus['type']) {
  if (type === 'success') {
    return 'text-emerald-200';
  }

  if (type === 'error') {
    return 'text-red-200';
  }

  return 'text-zinc-300';
}
