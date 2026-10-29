/**
 * Fixed-window rate limiter keyed by client identity.
 * Keeps memory bounded by evicting expired buckets on each sweep.
 */
class RateLimiter {
  constructor({ windowMs = 60_000, max = 120, maxKeys = 10_000 } = {}) {
    this.windowMs = windowMs;
    this.max = max;
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }

  consume(key) {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, bucket);
    }

    bucket.count++;

    if (this.buckets.size > this.maxKeys) this.sweep();

    const remaining = Math.max(0, this.max - bucket.count);
    return {
      allowed: bucket.count <= this.max,
      limit: this.max,
      remaining,
      resetAt: bucket.resetAt,
      retryAfterSec: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))
    };
  }

  sweep() {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }

    if (this.buckets.size > this.maxKeys) {
      const overflow = this.buckets.size - this.maxKeys;
      let removed = 0;
      for (const key of this.buckets.keys()) {
        this.buckets.delete(key);
        if (++removed >= overflow) break;
      }
    }
  }

  get size() {
    return this.buckets.size;
  }
}

function clientKey(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = (typeof forwarded === 'string' && forwarded.split(',')[0].trim()) ||
    req.ip ||
    req.socket?.remoteAddress ||
    'unknown';
  return ip;
}

/**
 * Express middleware factory.
 */
function rateLimit({ windowMs, max, maxKeys, skip } = {}) {
  const limiter = new RateLimiter({ windowMs, max, maxKeys });

  const middleware = (req, res, next) => {
    if (typeof skip === 'function' && skip(req)) return next();

    const result = limiter.consume(clientKey(req));
    res.setHeader('X-RateLimit-Limit', result.limit);
    res.setHeader('X-RateLimit-Remaining', result.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetAt / 1000));

    if (!result.allowed) {
      res.setHeader('Retry-After', result.retryAfterSec);
      return res.status(429).json({
        error: 'Too many requests',
        message: `Rate limit exceeded. Retry in ${result.retryAfterSec}s.`,
        retryAfterSec: result.retryAfterSec
      });
    }

    return next();
  };

  middleware.limiter = limiter;
  return middleware;
}

module.exports = { RateLimiter, rateLimit, clientKey };
