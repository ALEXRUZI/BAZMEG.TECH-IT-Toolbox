import { useLayoutEffect, useRef, useState } from 'react';

export const textCopyError = 'Could not copy automatically. Select the text below and copy it manually.';

// Only the latest attempt for the current displayed value may publish feedback.
export function useTextClipboard(text: string, successLabel = 'Copied') {
  const [status, setStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const attempt = useRef(0);
  const mounted = useRef(false);
  const timer = useRef<number | null>(null);

  function clearTimer() {
    if (timer.current !== null) {
      window.clearTimeout(timer.current);
      timer.current = null;
    }
  }

  function reset() {
    attempt.current += 1;
    clearTimer();
    if (mounted.current) setStatus('idle');
  }

  useLayoutEffect(() => {
    mounted.current = true;
    reset();
    return () => {
      mounted.current = false;
      attempt.current += 1;
      clearTimer();
    };
  }, [text, successLabel]);

  async function copy() {
    if (!mounted.current) return;
    reset();
    const currentAttempt = attempt.current;
    const isCurrent = () => mounted.current && attempt.current === currentAttempt;
    try {
      if (typeof navigator.clipboard?.writeText !== 'function') {
        throw new Error('Clipboard unavailable');
      }
      await navigator.clipboard.writeText(text);
      if (!isCurrent()) return;
      setStatus('success');
      timer.current = window.setTimeout(() => {
        timer.current = null;
        if (isCurrent()) setStatus('idle');
      }, 1400);
    } catch {
      if (isCurrent()) setStatus('error');
    }
  }

  return { copy, reset, copied: status === 'success', error: status === 'error' ? textCopyError : '' };
}
