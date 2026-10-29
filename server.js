const express = require('express');
const cors = require('cors');
const path = require('path');
const { lookupWhois, cleanDomain } = require('./lib/whois');
const { lookupAllDns, resolveRecordType, RECORD_TYPES } = require('./lib/dns');
const { checkPropagation } = require('./lib/propagation');
const { lookupIpInfo, isIpAddress } = require('./lib/ip');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/**
 * Unified lookup endpoint: WHOIS + DNS + Quick Propagation in parallel
 */
app.get('/api/lookup', async (req, res) => {
  const query = req.query.domain || req.query.q;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter "domain" is required.' });
  }

  const cleaned = cleanDomain(query);
  if (!cleaned) {
    return res.status(400).json({ error: 'Invalid domain or IP specified.' });
  }

  const startTime = Date.now();

  try {
    // If it's an IP address, handle as IP lookup
    if (isIpAddress(cleaned)) {
      const ipData = await lookupIpInfo(cleaned);
      return res.json({
        type: 'ip',
        query: cleaned,
        ip: ipData,
        durationMs: Date.now() - startTime
      });
    }

    // Run DNS & WHOIS queries concurrently
    const [dnsResult, whoisResult] = await Promise.allSettled([
      lookupAllDns(cleaned),
      lookupWhois(cleaned)
    ]);

    const dnsData = dnsResult.status === 'fulfilled' ? dnsResult.value : { error: dnsResult.reason.message };
    const whoisData = whoisResult.status === 'fulfilled' ? whoisResult.value : { error: whoisResult.reason.message };

    // Fetch Geo info for primary A record if available
    let primaryIpInfo = null;
    if (dnsData.recordsByType && dnsData.recordsByType['A'] && dnsData.recordsByType['A'].records.length > 0) {
      const firstA = dnsData.recordsByType['A'].records[0].value;
      try {
        primaryIpInfo = await lookupIpInfo(firstA);
      } catch (_) {}
    }

    res.json({
      type: 'domain',
      domain: cleaned,
      timestamp: new Date().toISOString(),
      dns: dnsData,
      whois: whoisData,
      primaryIp: primaryIpInfo,
      durationMs: Date.now() - startTime
    });
  } catch (err) {
    console.error('Unified lookup error:', err);
    res.status(500).json({
      error: 'Lookup failed',
      message: err.message
    });
  }
});

/**
 * WHOIS only endpoint
 */
app.get('/api/whois', async (req, res) => {
  const query = req.query.domain || req.query.q;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter "domain" is required.' });
  }

  const cleaned = cleanDomain(query);
  try {
    const data = await lookupWhois(cleaned);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: 'WHOIS lookup failed',
      message: err.message
    });
  }
});

/**
 * DNS records endpoint
 */
app.get('/api/dns', async (req, res) => {
  const query = req.query.domain || req.query.q;
  const type = (req.query.type || 'ALL').toUpperCase();

  if (!query) {
    return res.status(400).json({ error: 'Query parameter "domain" is required.' });
  }

  const cleaned = cleanDomain(query);

  try {
    if (type === 'ALL') {
      const data = await lookupAllDns(cleaned);
      return res.json(data);
    }

    if (!RECORD_TYPES.includes(type)) {
      return res.status(400).json({
        error: `Unsupported record type: ${type}`,
        supportedTypes: ['ALL', ...RECORD_TYPES]
      });
    }

    const data = await resolveRecordType(cleaned, type);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: 'DNS lookup failed',
      message: err.message
    });
  }
});

/**
 * Global DNS Propagation endpoint
 */
app.get('/api/propagation', async (req, res) => {
  const query = req.query.domain || req.query.q;
  const type = (req.query.type || 'A').toUpperCase();

  if (!query) {
    return res.status(400).json({ error: 'Query parameter "domain" is required.' });
  }

  const cleaned = cleanDomain(query);
  try {
    const data = await checkPropagation(cleaned, type);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: 'Propagation check failed',
      message: err.message
    });
  }
});

/**
 * IP lookup endpoint (PTR + GeoIP + ASN)
 */
app.get('/api/ip', async (req, res) => {
  const ip = req.query.ip || req.query.q;
  if (!ip) {
    return res.status(400).json({ error: 'Query parameter "ip" is required.' });
  }

  try {
    const data = await lookupIpInfo(ip);
    res.json(data);
  } catch (err) {
    res.status(500).json({
      error: 'IP lookup failed',
      message: err.message
    });
  }
});

/**
 * Fallback to index.html for SPA routing
 */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`DNS & WHOIS Web Tools running at http://localhost:${PORT}`);
  });
}

module.exports = app;
