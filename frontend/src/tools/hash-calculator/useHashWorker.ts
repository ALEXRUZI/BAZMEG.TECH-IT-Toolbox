import { useEffect, useRef, useState } from 'react';
import type { Digests, HashMessage, HashProgress, HashRequest } from './types';

type State = { status: 'idle' | 'running' | 'done' | 'cancelled' | 'error'; digests: Digests; progress: HashProgress; error: string };
const initial: State = { status: 'idle', digests: {}, progress: { processed: 0, total: 0, elapsedMs: 0 }, error: '' };

export function useHashWorker() {
  const worker = useRef<Worker | null>(null);
  const [state, setState] = useState<State>(initial);
  function stop() {
    const old = worker.current;
    worker.current = null; // Invalidate even already-queued callbacks before terminating.
    if (old) { old.onmessage = null; old.onerror = null; old.onmessageerror = null; old.terminate(); }
  }
  useEffect(() => () => stop(), []);
  function reset() { stop(); setState(initial); }
  function cancel() { stop(); setState((previous) => ({ ...previous, status: 'cancelled', digests: {} })); }
  function start(request: HashRequest) {
    stop();
    setState({ ...initial, status: 'running' });
    try {
      const current = new Worker(new URL('./hash.worker.ts', import.meta.url), { type: 'module' });
      worker.current = current;
      const fail = () => {
        if (worker.current !== current) return;
        stop();
        setState({ ...initial, status: 'error', error: 'The local hash worker failed. Retry; your browser may not support workers or WASM. No data was uploaded.' });
      };
      current.onerror = (event) => { event.preventDefault(); fail(); };
      current.onmessageerror = fail;
      current.onmessage = (event: MessageEvent<HashMessage>) => {
        if (worker.current !== current) return;
        const message = event.data;
        if (message.type === 'error') {
          stop(); setState({ ...initial, status: 'error', error: message.message });
        } else if (message.type === 'done') {
          stop(); setState({ status: 'done', digests: message.digests, progress: message, error: '' });
        } else setState({ status: 'running', digests: {}, progress: message, error: '' });
      };
      current.postMessage(request);
    } catch {
      stop(); setState({ ...initial, status: 'error', error: 'Could not start the local hash worker. Check browser support and retry. No data was uploaded.' });
    }
  }
  return { ...state, start, cancel, reset };
}
