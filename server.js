const express = require('express');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');
const path = require('path');
const { analyzeInput } = require('./lib/domain');
const { lookupWhois, whoisCache } = require('./lib/whois');
const { lookupAllDns, resolveRecordType, resolveChain, RECORD_TYPES, dnsCache } = require('./lib/dns');
const { checkPropagation, SUPPORTED_TYPES: PROPAGATION_TYPES } = require('./lib/propagation');
const { lookupIpInfo, ipCache } = require('./lib/ip');
const { rateLimit } = require('./lib/ratelimit');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_SERVERLESS = Boolean(process.env.VERCEL);

app.set('trust proxy', true);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://cloudflare-dns.com', 'https://dns.google'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
app.use(compression());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '16kb' }));

const apiLimiter = rateLimit({ windowMs: 60_000, max: 120 });

app.use('/api', apiLimiter);
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: IS_SERVERLESS ? '1h' : '7d',
  etag: true,
  index: false
}));

function sendError(res, status, message, extra = {}) {
  return res.status(status).json({ error: message, ...extra });
}

/**
 * Validate the "domain"/"q" query param into a normalized descriptor.
 */
function requireTarget(req, res) {
  const raw = req.query.domain ?? req.query.q;
  if (raw === undefined || raw === '') {
    sendError(res, 400, 'Query parameter "domain" is required.');
    return null;
  }

  const analyzed = analyzeInput(String(raw));
  if (!analyzed.ok) {
    sendError(res, 400, analyzed.reason, { input: String(raw).slice(0, 100) });
    return null;
  }

  return analyzed;
}

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: Math.round(process.uptime()),
    node: process.version,
    runtime: IS_SERVERLESS ? 'serverless' : 'node',
    caches: [whoisCache.stats(), dnsCache.stats(), ipCache.stats()]
  });
});

/**
 * Unified lookup: WHOIS + all DNS records + email auth + GeoIP.
 */
app.get('/api/lookup', async (req, res, next) => {
  const target = requireTarget(req, res);
  if (!target) return;

  const startedAt = Date.now();

  try {
    if (target.isIp) {
      const ipData = await lookupIpInfo(target.host);
      return res.json({
        type: 'ip',
        query: target.host,
        ip: ipData,
        durationMs: Date.now() - startedAt
      });
    }

    const [dnsResult, whoisResult] = await Promise.allSettled([
      lookupAllDns(target.host),
      lookupWhois(target.host)
    ]);

    if (dnsResult.status === 'rejected' && whoisResult.status === 'rejected') {
      return sendError(res, 502, 'Both DNS and WHOIS resolution failed.', {
        dns: dnsResult.reason?.message,
        whois: whoisResult.reason?.message
      });
    }

    const dnsData = dnsResult.status === 'fulfilled'
      ? dnsResult.value
      : { domain: target.host, recordsByType: {}, totalRecords: 0, healthChecks: [], error: dnsResult.reason?.message };

    const whoisData = whoisResult.status === 'fulfilled'
      ? whoisResult.value
      : { registrableDomain: target.registrable, error: whoisResult.reason?.message };

    let primaryIpInfo = null;
    const firstA = dnsData.recordsByType?.A?.records?.[0]?.value;
    if (firstA) {
      primaryIpInfo = await lookupIpInfo(firstA).catch(() => null);
    }

    const cnameChain = await resolveChain(target.host);

    res.json({
      type: 'domain',
      domain: target.host,
      registrableDomain: target.registrable,
      isSubdomain: target.isSubdomain,
      tld: target.publicSuffix,
      tldKnown: target.tldKnown,
      timestamp: new Date().toISOString(),
      dns: dnsData,
      whois: whoisData,
      cnameChain,
      primaryIp: primaryIpInfo,
      durationMs: Date.now() - startedAt
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/whois', async (req, res, next) => {
  const target = requireTarget(req, res);
  if (!target) return;
  if (target.isIp) {
    return sendError(res, 400, 'WHOIS lookup requires a domain name, not an IP address.');
  }

  try {
    res.json(await lookupWhois(target.host));
  } catch (err) {
    if (err.statusCode) return sendError(res, err.statusCode, err.message);
    next(err);
  }
});

app.get('/api/dns', async (req, res, next) => {
  const target = requireTarget(req, res);
  if (!target) return;

  const requestedType = String(req.query.type || 'ALL').toUpperCase();

  try {
    if (requestedType === 'ALL') {
      return res.json(await lookupAllDns(target.host));
    }

    if (!RECORD_TYPES.includes(requestedType)) {
      return sendError(res, 400, `Unsupported record type: ${requestedType}`, {
        supportedTypes: ['ALL', ...RECORD_TYPES]
      });
    }

    res.json(await resolveRecordType(target.host, requestedType));
  } catch (err) {
    next(err);
  }
});

app.get('/api/propagation', async (req, res, next) => {
  const target = requireTarget(req, res);
  if (!target) return;

  const requestedType = String(req.query.type || 'A').toUpperCase();
  if (!PROPAGATION_TYPES.includes(requestedType)) {
    return sendError(res, 400, `Unsupported propagation record type: ${requestedType}`, {
      supportedTypes: PROPAGATION_TYPES
    });
  }

  try {
    res.json(await checkPropagation(target.host, requestedType));
  } catch (err) {
    next(err);
  }
});

app.get('/api/ip', async (req, res, next) => {
  const ip = req.query.ip ?? req.query.q;
  if (ip === undefined || ip === '') {
    return sendError(res, 400, 'Query parameter "ip" is required.');
  }

  try {
    res.json(await lookupIpInfo(String(ip)));
  } catch (err) {
    if (err.statusCode) return sendError(res, err.statusCode, err.message);
    next(err);
  }
});

/**
 * Unknown API route must return JSON 404 rather than the SPA shell.
 */
app.use('/api', (req, res) => {
  sendError(res, 404, `Unknown API endpoint: ${req.method} /api${req.path}`, {
    endpoints: ['/api/health', '/api/lookup', '/api/whois', '/api/dns', '/api/propagation', '/api/ip']
  });
});

app.get('*', (req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (path.extname(req.path)) return next();
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res) => {
  sendError(res, 404, 'Not found.');
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  const status = err.statusCode || err.status || 500;
  sendError(res, status, status >= 500 ? 'Internal server error.' : err.message);
});

if (require.main === module && !IS_SERVERLESS) {
  const server = app.listen(PORT, () => {
    console.log(`WhoisDNS Web Tools running at http://localhost:${PORT}`);
  });

  const shutdown = signal => {
    console.log(`\n${signal} received, closing server...`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 8000).unref();
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

module.exports = app;
