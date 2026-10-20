import { useEffect, useRef, useState } from 'react';
import type { Request, Result } from './sshTypes';

export function useSshWorker() {
  const active = useRef<Worker | null>(null), timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [busy, setBusy] = useState(false), [result, setResult] = useState<Result | null>(null), [error, setError] = useState('');
  const [capabilities, setCapabilities] = useState<string[] | null>(null);
  function terminate() {
    const old = active.current; active.current = null;
    if (old) { old.onmessage = null; old.onerror = null; old.onmessageerror = null; old.terminate(); }
    if (timer.current) clearTimeout(timer.current); timer.current = null;
  }
  function clear() { terminate(); setBusy(false); setResult(null); setError(''); }
  useEffect(() => {
    if (!globalThis.isSecureContext || !globalThis.Worker || !crypto.subtle) { setCapabilities([]); return; }
    let worker: Worker;
    try { worker = new Worker(new URL('./ssh.worker.ts', import.meta.url), { type: 'module' }); }
    catch { setCapabilities([]); return; }
    let alive = true;
    const stopProbe = () => { alive = false; worker.onmessage = null; worker.onerror = null; worker.onmessageerror = null; worker.terminate(); };
    const deadline = setTimeout(() => { if (!alive) return; stopProbe(); setCapabilities([]); }, 30_000);
    worker.onmessage = (event: MessageEvent<{ supported: string[] }>) => { if (!alive) return; clearTimeout(deadline); stopProbe(); setCapabilities(Array.isArray(event.data.supported) ? event.data.supported : []); };
    const failProbe = () => { if (!alive) return; clearTimeout(deadline); stopProbe(); setCapabilities([]); };
    worker.onerror = (event) => { event.preventDefault(); failProbe(); };
    worker.onmessageerror = failProbe;
    worker.postMessage({ operation: 'capabilities' });
    return () => { clearTimeout(deadline); stopProbe(); terminate(); };
  }, []);
  function run(request: Request) {
    clear(); setBusy(true);
    try {
      const worker = new Worker(new URL('./ssh.worker.ts', import.meta.url), { type: 'module' }); active.current = worker;
      timer.current = setTimeout(() => { if (active.current !== worker) return; terminate(); setBusy(false); setError('Operation exceeded the 120-second work deadline. Try a smaller key or KDF workload.'); }, 120_000);
      worker.onmessage = (event: MessageEvent<{ result?: Result; error?: string }>) => {
        if (active.current !== worker) return;
        terminate(); setBusy(false); setResult(event.data.result ?? null); setError(event.data.error ?? '');
      };
      const fail = () => { if (active.current !== worker) return; terminate(); setBusy(false); setError('Cryptographic worker failed. No output was produced.'); };
      worker.onerror = (event) => { event.preventDefault(); fail(); };
      worker.onmessageerror = fail;
      worker.postMessage(request);
    } catch { terminate(); setBusy(false); setError('This browser cannot start the cryptographic worker.'); }
  }
  return { busy, result, error, capabilities, clear, run, setError };
}
