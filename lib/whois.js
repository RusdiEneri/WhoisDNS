const net = require('net');
const { analyzeInput } = require('./domain');
const { TtlCache, cached } = require('./cache');

const SOCKET_TIMEOUT_MS = 7000;
const MAX_RESPONSE_BYTES = 262144;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;
const TLD_LABEL_PATTERN = /^[a-z]{2,63}$/i;

/**
 * Decide whether a string may be written to a line-oriented WHOIS socket.
 * Bare TLD labels are only legal for the IANA TLD lookup, never for a domain query.
 */
function isQueryAllowed(value, options = {}) {
  const candidate = String(value || '');
  if (HOSTNAME_PATTERN.test(candidate)) return true;
  return Boolean(options.allowTld) && TLD_LABEL_PATTERN.test(candidate);
}


// Cache IANA TLD servers in-memory for speed
const tldCache = new TtlCache({ max: 500, ttlMs: 6 * 60 * 60 * 1000, name: 'whois-tld' });
const whoisCache = new TtlCache({ max: 500, ttlMs: 60 * 60 * 1000, name: 'whois' });

const WHOIS_CACHE_TTL_MS = 60 * 60 * 1000;
const WHOIS_ERROR_CACHE_TTL_MS = 60 * 1000;

/**
 * Execute raw socket query to port 43 WHOIS server.
 * The query must be a validated hostname: this is the only place untrusted
 * input crosses into a line-oriented protocol, so it is strictly filtered.
 */
function querySocket(server, query, timeoutMs = SOCKET_TIMEOUT_MS, options = {}) {
  return new Promise((resolve, reject) => {
    if (!isQueryAllowed(query, options)) {
      reject(new Error('Invalid query passed to WHOIS socket'));
      return;
    }
    if (!HOSTNAME_PATTERN.test(String(server || ''))) {
      reject(new Error('Invalid WHOIS server hostname'));
      return;
    }

    let settled = false;
    let bytes = 0;
    let data = '';

    let formattedQuery = `${query}\r\n`;
    if (server === 'whois.denic.de') {
      formattedQuery = `-T dn,ace ${formattedQuery}`;
    } else if (server === 'whois.jprs.jp') {
      formattedQuery = `${query}/e\r\n`;
    }

    const finish = (fn, payload) => {
      if (settled) return;
      settled = true;
      client.destroy();
      fn(payload);
    };

    const client = net.createConnection({ host: server, port: 43, timeout: timeoutMs }, () => {
      client.write(formattedQuery);
    });

    client.setEncoding('utf8');

    client.on('data', chunk => {
      bytes += Buffer.byteLength(chunk, 'utf8');
      data += chunk;
      if (bytes > MAX_RESPONSE_BYTES) {
        finish(resolve, data);
      }
    });

    client.on('timeout', () => {
      finish(resolve, data.trim() ? data : `Error: Timeout connecting to ${server}`);
    });

    client.on('end', () => finish(resolve, data));

    client.on('error', err => finish(reject, err));
  });
}

/**
 * Extract the TLD used for WHOIS server discovery.
 */
function getTld(domain) {
  const parts = String(domain || '').toLowerCase().split('.');
  return parts.length >= 2 ? parts[parts.length - 1] : '';
}

/**
 * Find authoritative WHOIS server for a TLD via IANA.
 */
async function getTldWhoisServer(tld) {
  const cachedServer = tldCache.get(tld);
  if (cachedServer) return cachedServer;

  try {
    const ianaResponse = await querySocket('whois.iana.org', tld, 6000, { allowTld: true });
    const match = ianaResponse.match(/^whois:\s*([^\s\r\n]+)/im);
    if (match && HOSTNAME_PATTERN.test(match[1].trim())) {
      const server = match[1].trim().toLowerCase();
      tldCache.set(tld, server);
      return server;
    }
  } catch (err) {
    console.warn(`IANA lookup failed for .${tld}:`, err.message);
  }

  return null;
}

/**
 * Get the registrable domain (eTLD+1) for a hostname.
 */
function cleanDomain(input) {
  const analyzed = analyzeInput(input);
  return analyzed.ok ? (analyzed.registrable || analyzed.host) : '';
}

function emptyWhois(domain) {
  return {
    domainName: domain,
    registryDomainId: null,
    registrar: null,
    registrarIanaId: null,
    registrarUrl: null,
    registrarAbuseEmail: null,
    registrarAbusePhone: null,
    creationDate: null,
    expiryDate: null,
    updatedDate: null,
    domainAge: null,
    daysUntilExpiry: null,
    status: [],
    nameServers: [],
    dnssec: null,
    registrant: { name: null, organization: null, country: null, state: null, email: null },
    isAvailable: false,
    raw: ''
  };
}

const NOT_FOUND_PATTERNS = [
  /no match for/i,
  /not found/i,
  /domain not found/i,
  /no data found/i,
  /status:\s*free/i,
  /status:\s*available/i,
  /no object found/i,
  /object does not exist/i,
  /the queried object does not exist/i,
  /no entries found/i,
  /^status:\s*(available|free)$/im
];

/** EURid and similar registries mark an unregistered name with this bare status. */
const AVAILABILITY_STATUS_VALUES = new Set(['available', 'free']);

/**
 * Normalise a registrar web address. Registries often publish a bare host
 * such as "www.example.com", which a browser would resolve as a relative
 * path against our own origin. Force an absolute https URL, and reject
 * anything that is not a plain web address.
 */
function normalizeUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw.replace(/^\/+/, '')}`;

  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch (_) {
    return null;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  if (!HOSTNAME_PATTERN.test(parsed.hostname)) return null;
  return parsed.toString().replace(/\/$/, '');
}

/**
 * Parse raw WHOIS response text into structured data.
 */
function parseWhois(rawText, domain) {
  const result = emptyWhois(domain);
  if (!rawText || typeof rawText !== 'string') return result;

  result.raw = rawText;
  result.isAvailable = NOT_FOUND_PATTERNS.some(p => p.test(rawText));

  let section = '';

  for (const line of rawText.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#') || trimmed.startsWith('>>>')) continue;

    const indented = /^[ \t]/.test(line);
    const colonIdx = trimmed.indexOf(':');

    // Section headers such as "Registrar:", "Name servers:" or "Keys:" carry
    // the key but no value, so the following indented lines belong to them.
    if (colonIdx === trimmed.length - 1) {
      section = trimmed.slice(0, -1).trim().toLowerCase();
      continue;
    }

    if (colonIdx === -1) {
      if (indented && section === 'name servers' && HOSTNAME_PATTERN.test(trimmed)) {
        const nsHost = trimmed.toLowerCase().replace(/\.$/, '');
        if (!result.nameServers.includes(nsHost)) result.nameServers.push(nsHost);
      }
      continue;
    }

    const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const value = trimmed.slice(colonIdx + 1).trim();
    if (!value) continue;

    // Nested EURid-style fields keyed by the section that owns them.
    if (section === 'registrar') {
      if (key === 'name') {
        if (!result.registrar) result.registrar = value;
        continue;
      }
      if (key === 'website') {
        if (!result.registrarUrl) result.registrarUrl = normalizeUrl(value);
        continue;
      }
    }
    if (section === 'keys' && key === 'flags' && /ksk/i.test(value)) {
      result.dnssec = 'signed';
      continue;
    }

    if (key === 'domain name' || key === 'domain') {
      if (!result.domainName || result.domainName === domain) {
        result.domainName = value.toLowerCase();
      }
    } else if (key === 'registry domain id') {
      result.registryDomainId = value;
    } else if (key === 'registrar' || key === 'sponsoring registrar') {
      if (!result.registrar) result.registrar = value;
    } else if (key === 'registrar iana id') {
      result.registrarIanaId = value;
    } else if (key === 'registrar url') {
      if (!result.registrarUrl) result.registrarUrl = normalizeUrl(value);
    } else if (key === 'registrar abuse contact email') {
      if (!result.registrarAbuseEmail) result.registrarAbuseEmail = value;
    } else if (key === 'registrar abuse contact phone') {
      if (!result.registrarAbusePhone) result.registrarAbusePhone = value;
    } else if (['creation date', 'created', 'registration time', 'registered on', 'domain registration date'].includes(key)) {
      if (!result.creationDate) result.creationDate = value;
    } else if ([
      'registry expiry date',
      'registrar registration expiration date',
      'expiry date',
      'expiration date',
      'paid-till',
      'expires on'
    ].includes(key)) {
      if (!result.expiryDate) result.expiryDate = value;
    } else if (['updated date', 'last updated', 'last-update', 'modified', 'changed'].includes(key)) {
      if (!result.updatedDate) result.updatedDate = value;
    } else if (key === 'domain status' || key === 'status') {
      const statusCode = value.split(/\s+/)[0].trim();
      // AVAILABLE/FREE is an availability marker, not an EPP state.
      if (AVAILABILITY_STATUS_VALUES.has(statusCode.toLowerCase())) {
        result.isAvailable = true;
        continue;
      }
      if (statusCode && !result.status.includes(statusCode)) result.status.push(statusCode);
    } else if (key === 'name server' || key === 'nserver' || key === 'nameservers') {
      const nsHost = value.split(/\s+/)[0].toLowerCase().replace(/\.$/, '');
      if (nsHost && !result.nameServers.includes(nsHost)) result.nameServers.push(nsHost);
    } else if (key === 'dnssec') {
      result.dnssec = value;
    } else if (key === 'registrant name') {
      result.registrant.name = value;
    } else if (key === 'registrant organization' || key === 'registrant org') {
      result.registrant.organization = value;
    } else if (key === 'registrant country') {
      result.registrant.country = value;
    } else if (key === 'registrant state/province' || key === 'registrant state') {
      result.registrant.state = value;
    } else if (key === 'registrant email') {
      result.registrant.email = value;
    }
  }

  const created = result.creationDate ? new Date(result.creationDate) : null;
  if (created && !Number.isNaN(created.getTime())) {
    const days = Math.floor((Date.now() - created.getTime()) / 86400000);
    result.domainAge = `${(days / 365.25).toFixed(1)} years (${days.toLocaleString('en-US')} days)`;
  }

  const expires = result.expiryDate ? new Date(result.expiryDate) : null;
  if (expires && !Number.isNaN(expires.getTime())) {
    result.daysUntilExpiry = Math.floor((expires.getTime() - Date.now()) / 86400000);
  }

  return result;
}

/**
 * Fallback to RDAP when the port 43 socket fails.
 */
async function queryRdap(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'User-Agent': 'WhoisDNS-Tools/1.0 (+https://github.com)',
        Accept: 'application/rdap+json, application/json'
      },
      signal: AbortSignal.timeout(6000)
    });
    if (res.ok) return await res.json();
  } catch (_) {
    // ignore RDAP failure, caller falls back to socket error
  }
  return null;
}

function mapRdap(rdapData, domain) {
  const result = emptyWhois((rdapData.ldhName || domain).toLowerCase());
  result.registryDomainId = rdapData.handle || null;
  result.status = (rdapData.status || []).map(s => String(s));
  result.nameServers = (rdapData.nameservers || [])
    .map(ns => (ns.ldhName || '').toLowerCase())
    .filter(Boolean);
  result.dnssec = rdapData.secureDNS
    ? (rdapData.secureDNS.delegationSigned ? 'signed' : 'unsigned')
    : null;
  result.raw = JSON.stringify(rdapData, null, 2);

  for (const event of rdapData.events || []) {
    if (event.eventAction === 'registration') result.creationDate = event.eventDate;
    if (event.eventAction === 'expiration') result.expiryDate = event.eventDate;
    if (event.eventAction === 'last changed') result.updatedDate = event.eventDate;
  }

  for (const entity of rdapData.entities || []) {
    const roles = entity.roles || [];
    const vcard = Array.isArray(entity.vcardArray) ? entity.vcardArray[1] || [] : [];
    const field = name => {
      const item = vcard.find(entry => entry[0] === name);
      return item ? item[3] : null;
    };

    if (roles.includes('registrar')) {
      result.registrar = result.registrar || field('fn');
      result.registrarAbuseEmail = result.registrarAbuseEmail || field('email');
    }
    if (roles.includes('registrant')) {
      result.registrant.name = result.registrant.name || field('fn');
      result.registrant.organization = result.registrant.organization || field('org');
    }
  }

  const created = result.creationDate ? new Date(result.creationDate) : null;
  if (created && !Number.isNaN(created.getTime())) {
    const days = Math.floor((Date.now() - created.getTime()) / 86400000);
    result.domainAge = `${(days / 365.25).toFixed(1)} years (${days.toLocaleString('en-US')} days)`;
  }
  const expires = result.expiryDate ? new Date(result.expiryDate) : null;
  if (expires && !Number.isNaN(expires.getTime())) {
    result.daysUntilExpiry = Math.floor((expires.getTime() - Date.now()) / 86400000);
  }

  return result;
}

async function queryWhoisRaw(domain, tld) {
  const primaryServer = await getTldWhoisServer(tld);
  if (!primaryServer) {
    const rdap = await queryRdap(domain);
    if (rdap) return mapRdap(rdap, domain);
    throw new Error(`No WHOIS server could be discovered for .${tld}`);
  }

  let rawText;
  try {
    rawText = await querySocket(primaryServer, domain);
  } catch (socketErr) {
    const rdap = await queryRdap(domain);
    if (rdap) return mapRdap(rdap, domain);
    throw new Error(`WHOIS query failed: ${socketErr.message}`);
  }

  rawText = String(rawText || '');
  if (/^(error:|connect:|referral timeout)/i.test(rawText.trim())) {
    const rdap = await queryRdap(domain);
    if (rdap) return mapRdap(rdap, domain);
  }

  const referralMatch = rawText.match(/^(?:registrar whois server|whois server|refer):\s*([a-z0-9.-]+\.[a-z]{2,})/im);
  const referralServer = referralMatch ? referralMatch[1].trim().toLowerCase() : null;

  if (referralServer && referralServer !== primaryServer && HOSTNAME_PATTERN.test(referralServer)) {
    try {
      const secondResponse = await querySocket(referralServer, domain);
      if (secondResponse && secondResponse.trim().length > 100) {
        rawText += `\n\n--- REGISTRAR WHOIS SERVER RESPONSE (${referralServer}) ---\n\n${secondResponse}`;
      }
    } catch (subErr) {
      console.warn(`Referral query to ${referralServer} failed:`, subErr.message);
    }
  }

  return parseWhois(rawText, domain);
}

/**
 * Main WHOIS query. Always queries the registrable domain (eTLD+1) so that
 * subdomains are not reported as "available".
 */
async function lookupWhois(inputDomain, options = {}) {
  const analyzed = analyzeInput(inputDomain);
  if (!analyzed.ok) {
    const err = new Error(analyzed.reason);
    err.statusCode = 400;
    throw err;
  }
  if (analyzed.isIp) {
    const err = new Error('WHOIS lookup requires a domain name, not an IP address.');
    err.statusCode = 400;
    throw err;
  }

  const domain = analyzed.registrable;
  const tld = getTld(domain);
  const cacheKey = `whois:${domain}`;

  const { value, cached: fromCache } = await cached(
    whoisCache,
    cacheKey,
    async () => {
      try {
        const data = await queryWhoisRaw(domain, tld);
        data.queriedHost = analyzed.host;
        data.registrableDomain = domain;
        data.fromCache = false;
        return data;
      } catch (err) {
        if (err.statusCode) throw err;
        return {
          ...emptyWhois(domain),
          error: err.message,
          queriedHost: analyzed.host,
          registrableDomain: domain,
          fromCache: false
        };
      }
    },
    WHOIS_CACHE_TTL_MS
  );

  return {
    ...value,
    queriedHost: analyzed.host,
    registrableDomain: domain,
    isSubdomain: analyzed.isSubdomain,
    fromCache
  };
}

module.exports = {
  lookupWhois,
  cleanDomain,
  getTld,
  parseWhois,
  querySocket,
  isQueryAllowed,
  whoisCache
};
