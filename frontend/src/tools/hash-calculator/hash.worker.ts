import { calculateHashes, HashFailure } from './engine';
import type { HashMessage, HashRequest } from './types';

const send = (message: HashMessage) => self.postMessage(message);
self.onmessage = async (event: MessageEvent<HashRequest>) => {
  try {
    const result = await calculateHashes(event.data, (value) => send({ type: 'progress', ...value }));
    send({ type: 'done', ...result });
  } catch (error) {
    send({ type: 'error', message: error instanceof HashFailure ? error.message : 'Local hashing failed. Retry or select the input again. No data was uploaded.' });
  }
};
