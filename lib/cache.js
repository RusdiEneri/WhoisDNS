const registry = new Set();

/**
 * Minimal in-memory TTL cache with a hard entry cap (LRU-ish eviction).
 */
class TtlCache {
  constructor({ max = 1000, ttlMs = 60000, name = 'cache' } = {}) {
    this.max = max;
    this.ttlMs = ttlMs;
    this.name = name;
    this.store = new Map();
    this.hits = 0;
    this.misses = 0;
    registry.add(this);
  }

  get(key) {
    const entry = this.store.get(key);
    if (!entry) {
      this.misses++;
      return undefined;
    }

    if (entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      this.misses++;
      return undefined;
    }

    this.store.delete(key);
    this.store.set(key, entry);
    this.hits++;
    return entry.value;
  }

  set(key, value, ttlMs = this.ttlMs) {
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs });

    while (this.store.size > this.max) {
      this.store.delete(this.store.keys().next().value);
    }

    return value;
  }

  has(key) {
    return this.get(key) !== undefined;
  }

  delete(key) {
    return this.store.delete(key);
  }

  clear() {
    this.store.clear();
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAt <= now) this.store.delete(key);
    }
  }

  get size() {
    return this.store.size;
  }

  stats() {
    const total = this.hits + this.misses;
    return {
      name: this.name,
      size: this.store.size,
      max: this.max,
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? Number((this.hits / total).toFixed(3)) : 0
    };
  }
}

/**
 * Cache wrapper that reports whether the value came from cache.
 */
async function cached(cache, key, producer, ttlMs) {
  const hit = cache.get(key);
  if (hit !== undefined) {
    return { value: hit, cached: true };
  }

  const value = await producer();
  if (value !== undefined && value !== null) {
    cache.set(key, value, ttlMs);
  }
  return { value, cached: false };
}

const sweeper = setInterval(() => {
  for (const cache of registry) cache.sweep();
}, 5 * 60 * 1000);
if (typeof sweeper.unref === 'function') sweeper.unref();

module.exports = { TtlCache, cached };
