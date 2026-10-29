/**
 * DNS-over-HTTPS (RFC 8484 JSON API) client.
 * DoH is used as the primary source because the wire format exposes TTL for
 * every record type, which the native Node resolver only returns for A/AAAA.
 */

const DOH_PROVIDERS = [
  { id: 'cloudflare', name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { id: 'google', name: 'Google', url: 'https://dns.google/resolve' }
];

const TYPE_CODES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
  CAA: 257,
  HTTPS: 65,
  SVCB: 64
};

const CODE_TYPES = Object.fromEntries(Object.entries(TYPE_CODES).map(([k, v]) => [v, k]));

const RCODE_MESSAGES = {
  0: null,
  1: 'Malformed DNS query',
  2: 'DNS server failure',
  3: 'NXDOMAIN: domain does not exist',
  4: 'Not implemented by resolver',
  5: 'DNS query refused by resolver'
};

async function queryProvider(provider, name, type, timeoutMs = 5000) {
  const url = `${provider.url}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&cd=0`;
  const res = await fetch(url, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(timeoutMs)
  });

  if (!res.ok) throw new Error(`DoH ${provider.id} HTTP ${res.status}`);
  return { json: await res.json(), provider: provider.id };
}

/**
 * Resolve a name+type through DoH with automatic provider failover.
 * Returns raw DoH JSON plus the provider that answered.
 */
async function dohQuery(name, type, { timeoutMs = 5000 } = {}) {
  const errors = [];

  for (const provider of DOH_PROVIDERS) {
    try {
      return await queryProvider(provider, name, type, timeoutMs);
    } catch (err) {
      errors.push(`${provider.id}: ${err.message}`);
    }
  }

  const error = new Error(`All DoH providers failed (${errors.join('; ')})`);
  error.code = 'DOH_FAILURE';
  throw error;
}

function stripTrailingDot(value) {
  return String(value || '').replace(/\.$/, '');
}

function unquoteTxt(data) {
  const matches = String(data || '').match(/"((?:[^"\\]|\\.)*)"/g);
  if (!matches) return String(data || '');
  return matches
    .map(chunk => chunk.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\'))
    .join('');
}

/**
 * Convert one DoH answer entry into the flat record shape the UI expects.
 */
function normalizeAnswer(answer, queryName, type) {
  const ttl = typeof answer.TTL === 'number' ? answer.TTL : null;
  const raw = String(answer.data || '');
  const base = { type, ttl, raw };

  switch (type) {
    case 'A':
    case 'AAAA':
      return { ...base, value: raw };

    case 'CNAME':
    case 'NS':
    case 'PTR':
      return { ...base, value: stripTrailingDot(raw).toLowerCase() };

    case 'MX': {
      const [priority, exchange] = raw.split(/\s+/);
      const host = stripTrailingDot(exchange || '').toLowerCase();
      return {
        ...base,
        priority: Number(priority),
        exchange: host,
        value: `${host} (Priority: ${priority})`
      };
    }

    case 'TXT': {
      const value = unquoteTxt(raw);
      let subtype = 'General';
      if (/^v=spf1/i.test(value)) subtype = 'SPF';
      else if (/^v=DMARC1/i.test(value)) subtype = 'DMARC';
      else if (/^v=DKIM1/i.test(value)) subtype = 'DKIM';
      else if (/google-site-verification/i.test(value)) subtype = 'Google Verification';
      else if (/MS=|v=ms/i.test(value)) subtype = 'Microsoft Verification';
      else if (/apple-domain-verification/i.test(value)) subtype = 'Apple Verification';
      else if (/facebook-domain-verification/i.test(value)) subtype = 'Facebook Verification';
      else if (/^v=BIMI1/i.test(value)) subtype = 'BIMI';
      return { ...base, subtype, name: answer.name, value };
    }

    case 'SOA': {
      const parts = raw.split(/\s+/);
      return {
        ...base,
        nsname: stripTrailingDot(parts[0] || '').toLowerCase(),
        hostmaster: stripTrailingDot(parts[1] || '').toLowerCase(),
        serial: Number(parts[2]) || null,
        refresh: Number(parts[3]) || null,
        retry: Number(parts[4]) || null,
        expire: Number(parts[5]) || null,
        minttl: Number(parts[6]) || null,
        value: `Primary: ${stripTrailingDot(parts[0] || '')} | Admin: ${stripTrailingDot(parts[1] || '')} | Serial: ${parts[2] || '-'}`
      };
    }

    case 'CAA': {
      const match = raw.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?$/);
      const critical = match ? Number(match[1]) : 0;
      const tag = match ? match[2] : 'unknown';
      const value = match ? match[3] : raw;
      return { ...base, critical, tag, value: `${tag} "${value}"` };
    }

    case 'SRV': {
      const [priority, weight, port, target] = raw.split(/\s+/);
      const host = stripTrailingDot(target || '').toLowerCase();
      return {
        ...base,
        priority: Number(priority),
        weight: Number(weight),
        port: Number(port),
        name: host,
        prefix: stripTrailingDot(queryName).replace(/\.[^.]+$/, ''),
        value: `${host}:${port} (Pri: ${priority}, Wgt: ${weight})`
      };
    }

    case 'NAPTR': {
      const parts = raw.split(/\s+/);
      return {
        ...base,
        order: Number(parts[0]),
        preference: Number(parts[1]),
        value: raw
      };
    }

    case 'DS':
    case 'DNSKEY':
    case 'TLSA':
    case 'HTTPS':
    case 'SVCB':
    default:
      return { ...base, value: raw };
  }
}

module.exports = {
  DOH_PROVIDERS,
  TYPE_CODES,
  CODE_TYPES,
  RCODE_MESSAGES,
  dohQuery,
  normalizeAnswer,
  unquoteTxt,
  stripTrailingDot
};
