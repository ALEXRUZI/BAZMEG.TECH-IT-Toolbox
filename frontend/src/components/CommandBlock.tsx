import { CopyButton } from './CopyButton';
import { useTextClipboard } from './useTextClipboard';

export function CommandBlock({ children, scrollInside = false }: { children: string; scrollInside?: boolean }) {
  const { copy, copied, error } = useTextClipboard(children);
  const preClassName = scrollInside
    ? 'max-h-[70vh] overflow-auto p-4 text-sm text-zinc-100'
    : 'overflow-x-auto p-4 text-sm text-zinc-100';

  return (
    <div className="mt-4 max-w-full overflow-hidden rounded-2xl bg-zinc-950">
      <div className="flex items-center justify-end border-b border-white/10 px-3 py-2">
        <CopyButton onClick={copy}>{copied ? 'Copied' : 'Copy'}</CopyButton>
      </div>
      <p role="status" className={error ? 'px-4 pt-3 text-sm text-red-300' : 'sr-only'}>
        {error || (copied ? 'Copied' : '')}
      </p>
      <pre className={preClassName}>{children}</pre>
    </div>
  );
}
