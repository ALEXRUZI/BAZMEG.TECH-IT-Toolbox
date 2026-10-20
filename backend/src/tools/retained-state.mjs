// Process-local retention only. Callers own clocks, errors, and token accounting.
export const RETENTION_LIMITS = Object.freeze({
  cacheEntries: 512,
  cacheResponseBytes: 256 * 1024,
  dnsClients: 8192,
  httpClients: 4096,
  httpTargets: 4096,
  httpGlobalHistory: 4200,
});

export class BoundedCache {
  constructor(capacity = RETENTION_LIMITS.cacheEntries, maxBytes = RETENTION_LIMITS.cacheResponseBytes) {
    this.entries = new Map();
    this.capacity = capacity;
    this.maxBytes = maxBytes;
  }

  prune(now) {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  get(key, now) {
    this.prune(now);
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      this.entries.set(key, entry);
    }
    return entry;
  }

  set(key, entry, now, assertLive = () => {}) {
    this.setMany([[key, entry]], now, assertLive);
  }

  setMany(entries, now, assertLive = () => {}) {
    this.prune(now);
    // Oversized/expired results are returned intact, but not retained.
    const eligible = entries.filter(([, entry]) => entry.expiresAt > now
      && Buffer.byteLength(JSON.stringify(entry.response)) <= this.maxBytes);
    // Serialize all staged protocols before the deadline check; publication is
    // synchronous so cancellation cannot publish only half of a Both result.
    assertLive();
    for (const [key, entry] of eligible) {
      this.entries.delete(key);
      if (this.entries.size >= this.capacity) this.entries.delete(this.entries.keys().next().value);
      this.entries.set(key, entry);
    }
  }

  get size() { return this.entries.size; }
  clear() { this.entries.clear(); }
}

export function pruneHistory(bucket, now, windowMs) {
  let retained = 0;
  for (let index = 0; index < bucket.length; index += 1) {
    if (now - bucket[index].time < windowMs) bucket[retained++] = bucket[index];
  }
  bucket.length = retained;
}

export class BoundedRateHistory {
  constructor(capacity, maxHistory, windowMs = 3_600_000) {
    this.entries = new Map();
    this.capacity = capacity;
    this.maxHistory = maxHistory;
    this.windowMs = windowMs;
    this.cursor = this.entries.keys();
  }

  pruneKey(key, now) {
    const bucket = this.entries.get(key);
    if (!bucket) return;
    pruneHistory(bucket, now, this.windowMs);
    if (!bucket.length) this.entries.delete(key);
  }

  prune(now, full = false) {
    if (full) {
      for (const key of this.entries.keys()) this.pruneKey(key, now);
      this.cursor = this.entries.keys();
      return;
    }
    // Fixed incremental work, independent of adversarial key churn.
    for (let index = 0; index < 16; index += 1) {
      let next = this.cursor.next();
      if (next.done) {
        this.cursor = this.entries.keys();
        next = this.cursor.next();
        if (next.done) break;
      }
      this.pruneKey(next.value, now);
    }
  }

  prepare(key, now, error) {
    this.pruneKey(key, now);
    if (!this.entries.has(key) && this.entries.size >= this.capacity) this.prune(now, true);
    if (!this.entries.has(key) && this.entries.size >= this.capacity) throw error();
    return this.entries.get(key) || [];
  }

  commit(key, bucket, cost, now, error) {
    // Check before insertion, even for callers that did not prepare first.
    if ((!this.entries.has(key) && this.entries.size >= this.capacity) || bucket.length >= this.maxHistory) throw error();
    bucket.push({ time: now, cost });
    this.entries.set(key, bucket);
  }

  get size() { return this.entries.size; }
  clear() { this.entries.clear(); this.cursor = this.entries.keys(); }
}
