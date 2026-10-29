const dns = require('dns');

/**
 * Autonomous systems / public resolver endpoints used for propagation checks.
 */
const GLOBAL_RESOLVERS = [
  { id: 'cloudflare', name: 'Cloudflare DNS', ip: '1.1.1.1', location: 'Global Anycast', provider: 'Cloudflare' },
  { id: 'google', name: 'Google Public DNS', ip: '8.8.8.8', location: 'Global Anycast', provider: 'Google LLC' },
  { id: 'quad9', name: 'Quad9 Security', ip: '9.9.9.9', location: 'Zurich, Switzerland', provider: 'Quad9 Foundation' },
  { id: 'opendns', name: 'OpenDNS Umbrella', ip: '208.67.222.222', location: 'San Francisco, USA', provider: 'Cisco Systems' },
  { id: 'adguard', name: 'AdGuard DNS', ip: '94.140.14.14', location: 'Cyprus / EU', provider: 'AdGuard Software' },
  { id: 'comodo', name: 'Comodo Secure DNS', ip: '8.26.56.26', location: 'Clifton, USA', provider: 'Sectigo' },
  { id: 'level3', name: 'Lumen / Level3', ip: '4.2.2.2', location: 'Broomfield, USA', provider: 'Lumen Technologies' },
  { id: 'dns-sb', name: 'DNS.SB Privacy', ip: '185.222.222.222', location: 'Frankfurt, Germany', provider: 'DNS.SB' }
];

const SUPPORTED_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'SRV', 'PTR', 'HTTPS', 'SVCB', 'DS', 'DNSKEY', 'TLSA', 'NAPTR'];

function resolveWith(resolver, domain, recordType) {
  switch (recordType) {
    case 'A':
      return resolver.resolve4(domain);
    case 'AAAA':
      return resolver.resolve6(domain);
    case 'MX':
      return resolver.resolveMx(domain).then(mx => mx.map(m => `${m.exchange} (${m.priority})`));
    case 'TXT':
      return resolver.resolveTxt(domain).then(txt => txt.map(chunks => chunks.join('')));
    case 'NS':
      return resolver.resolveNs(domain).then(ns => ns.map(n => n.toLowerCase()));
    case 'CNAME':
      return resolver.resolveCname(domain);
    case 'SOA':
      return resolver.resolveSoa(domain).then(soa => [`${soa.nsname} serial=${soa.serial}`]);
    case 'CAA':
      return resolver.resolveCaa(domain).then(caa =>
        caa.map(c => `${c.critical ?? 0} ${c.tag || c.issue || c.iodef || 'issue'} ${c.value || c.issue || c.iodef || ''}`.trim())
      );
    case 'SRV':
      return resolver.resolveSrv(domain).then(srv =>
        srv.map(s => `${s.name}:${s.port} pri=${s.priority} wgt=${s.weight}`)
      );
    case 'PTR':
      return resolver.resolvePtr ? resolver.resolvePtr(domain) : resolver.reverse(domain);
    default:
      return resolver.resolve4(domain);
  }
}

/**
 * Query a specific resolver for a domain and record type, cancelling the
 * resolver channel on timeout so no handles leak.
 */
async function querySingleResolver(resolverConfig, domain, recordType = 'A', timeoutMs = 5000) {
  const resolver = new dns.promises.Resolver();
  resolver.setServers([resolverConfig.ip]);

  const startTime = Date.now();
  let timer = null;

  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      if (typeof resolver.cancel === 'function') resolver.cancel();
      reject(new Error(`Resolver timeout after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  try {
    const records = await Promise.race([resolveWith(resolver, domain, recordType), timeout]);
    return {
      ...resolverConfig,
      status: 'resolved',
      success: true,
      records: Array.isArray(records) ? records : [records],
      durationMs: Date.now() - startTime
    };
  } catch (err) {
    const isNotFound = ['ENODATA', 'ENOTFOUND'].includes(err.code);
    return {
      ...resolverConfig,
      status: isNotFound ? 'no_record' : 'error',
      success: isNotFound,
      records: [],
      error: isNotFound ? 'No record found' : err.message,
      errorCode: err.code || null,
      durationMs: Date.now() - startTime
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Check propagation across all global resolvers.
 */
async function checkPropagation(domain, recordType = 'A') {
  const startTime = Date.now();
  const normalizedType = String(recordType || 'A').toUpperCase();
  const type = SUPPORTED_TYPES.includes(normalizedType) ? normalizedType : 'A';

  const results = await Promise.all(
    GLOBAL_RESOLVERS.map(r => querySingleResolver(r, domain, type))
  );

  const valueGroups = new Map();
  let resolvedCount = 0;

  for (const res of results) {
    if (res.success && res.records.length > 0) {
      resolvedCount++;
      const key = [...res.records].sort().join(' | ');
      if (!valueGroups.has(key)) {
        valueGroups.set(key, { sample: res.records, resolvers: [] });
      }
      valueGroups.get(key).resolvers.push(res.name);
    }
  }

  const total = results.length;
  let propagationStatus = 'complete';
  if (resolvedCount === 0) propagationStatus = 'none';
  else if (valueGroups.size > 1) propagationStatus = 'divergent';
  else if (resolvedCount < total) propagationStatus = 'in_progress';

  return {
    domain,
    recordType: type,
    propagationStatus,
    resolvedCount,
    totalResolvers: total,
    percentage: Math.round((resolvedCount / total) * 100),
    consistent: valueGroups.size <= 1,
    groups: Array.from(valueGroups.entries()).map(([, v]) => ({
      records: v.sample,
      matchingResolvers: v.resolvers,
      count: v.resolvers.length
    })),
    resolvers: results,
    totalDurationMs: Date.now() - startTime
  };
}

module.exports = {
  checkPropagation,
  GLOBAL_RESOLVERS,
  SUPPORTED_TYPES
};
