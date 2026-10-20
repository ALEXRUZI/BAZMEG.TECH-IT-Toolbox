import { CopyButton } from '../../components/CopyButton';
import { useTextClipboard } from '../../components/useTextClipboard';

export function DigestResult({ label, digest }: { label: string; digest: string }) {
  const { copy, copied, error } = useTextClipboard(digest);
  return <section aria-label={`${label} digest`} className="min-w-0 rounded-2xl border border-white/10 bg-zinc-950/60 p-4">
    <div className="flex items-center justify-between gap-3">
      <h3 className="text-sm font-semibold text-zinc-300">{label}</h3>
      <CopyButton aria-label={`Copy ${label} digest`} onClick={copy}>{copied ? 'Copied' : 'Copy'}</CopyButton>
    </div>
    <p className="mt-3 break-all font-mono text-sm text-zinc-100">{digest}</p>
    <p role="status" className={error ? 'mt-2 text-sm text-red-300' : 'sr-only'}>{error || (copied ? 'Copied' : '')}</p>
  </section>;
}
