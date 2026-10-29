const { Resolver } = require('dns').promises;

/**
 * List of global authoritative public resolvers for propagation testing
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

/**
 * Query a specific resolver for a domain and record type
 */
async function querySingleResolver(resolverConfig, domain, recordType = 'A', timeoutMs = 5000) {
  const resolver = new Resolver();
  resolver.setServers([resolverConfig.ip]);

  const startTime = Date.now();
  const queryPromise = (async () => {
    switch (recordType.toUpperCase()) {
      case 'A': {
        const ips = await resolver.resolve4(domain);
        return ips;
      }
      case 'AAAA': {
        const ips = await resolver.resolve6(domain);
        return ips;
      }
      case 'MX': {
        const mx = await resolver.resolveMx(domain);
        return mx.map(m => `${m.exchange} (${m.priority})`);
      }
      case 'TXT': {
        const txt = await resolver.resolveTxt(domain);
        return txt.map(chunks => chunks.join(''));
      }
      case 'NS': {
        const ns = await resolver.resolveNs(domain);
        return ns.map(n => n.toLowerCase());
      }
      case 'CNAME': {
        const cname = await resolver.resolveCname(domain);
        return cname;
      }
      default: {
        const ips = await resolver.resolve4(domain);
        return ips;
      }
    }
  })();

  try {
    const records = await Promise.race([
      queryPromise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Resolver timeout')), timeoutMs))
    ]);

    const durationMs = Date.now() - startTime;
    return {
      ...resolverConfig,
      status: 'resolved',
      success: true,
      records: Array.isArray(records) ? records : [records],
      durationMs
    };
  } catch (err) {
    const durationMs = Date.now() - startTime;
    const isNotFound = ['ENODATA', 'ENOTFOUND'].includes(err.code);
    return {
      ...resolverConfig,
      status: isNotFound ? 'no_record' : 'error',
      success: isNotFound,
      records: [],
      error: isNotFound ? 'No record found' : err.message,
      durationMs
    };
  }
}

/**
 * Check propagation across all global resolvers
 */
async function checkPropagation(domain, recordType = 'A') {
  const startTime = Date.now();
  const promises = GLOBAL_RESOLVERS.map(r => querySingleResolver(r, domain, recordType));
  const results = await Promise.all(promises);

  // Group resolved values to detect consistency
  const valueGroups = new Map();
  let resolvedCount = 0;

  results.forEach(res => {
    if (res.success && res.records.length > 0) {
      resolvedCount++;
      const sortedKey = [...res.records].sort().join(' | ');
      if (!valueGroups.has(sortedKey)) {
        valueGroups.set(sortedKey, {
          sample: res.records,
          resolvers: []
        });
      }
      valueGroups.get(sortedKey).resolvers.push(res.name);
    }
  });

  const total = results.length;
  let propagationStatus = 'complete';

  if (resolvedCount === 0) {
    propagationStatus = 'none';
  } else if (valueGroups.size > 1) {
    propagationStatus = 'divergent'; // different IPs in different regions
  } else if (resolvedCount < total) {
    propagationStatus = 'in_progress';
  }

  return {
    domain,
    recordType,
    propagationStatus,
    resolvedCount,
    totalResolvers: total,
    percentage: Math.round((resolvedCount / total) * 100),
    groups: Array.from(valueGroups.entries()).map(([k, v]) => ({
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
  GLOBAL_RESOLVERS
};
