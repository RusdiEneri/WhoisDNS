const {
  dohQuery,
  normalizeAnswer,
  RCODE_MESSAGES,
  stripTrailingDot
} = require('./doh');
const { TtlCache } = require('./cache');

const RECORD_TYPES = [
  'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'SRV',
  'HTTPS', 'SVCB', 'DS', 'DNSKEY', 'TLSA', 'NAPTR'
];

const COMMON_SRV_PREFIXES = [
  '_autodiscover._tcp',
  '_sip._tls',
  '_sip._tcp',
  '_xmpp-server._tcp',
  '_submission._tcp',
  '_imap._tcp',
  '_carddavs._tcp'
];

const COMMON_TLSA_PORTS = ['_443._tcp', '_25._tcp'];

const dnsCache = new TtlCache({ max: 2000, ttlMs: 5 * 60 * 1000, name: 'dns' });
const DNS_CACHE_TTL_MS = 5 * 60 * 1000;
const QUERY_TIMEOUT_MS = 5000;

function ttlFromAnswers(answers) {
  const ttls = answers.map(a => a.ttl).filter(t => typeof t === 'number' && t > 0);
  return ttls.length ? Math.min(...ttls) : DNS_CACHE_TTL_MS / 1000;
}

async function queryNameType(name, type, { queryName } = {}) {
  const target = queryName || name;

  let response;
  try {
    response = await dohQuery(target, type, { timeoutMs: QUERY_TIMEOUT_MS });
  } catch (err) {
    return {
      type,
      success: false,
      records: [],
      count: 0,
      error: err.message,
      errorCode: err.code || 'DOH_ERROR',
      durationMs: 0
    };
  }

  const { json } = response;
  const answers = Array.isArray(json.Answer) ? json.Answer : [];
  const wantedCode = require('./doh').TYPE_CODES[type];
  const relevant = answers.filter(a => a.type === wantedCode);

  const records = relevant.map(a => normalizeAnswer(a, target, type));

  if (type === 'TXT' && records.length === 0 && answers.length > 0) {
    const txtLike = answers.filter(a => a.type === 16);
    records.push(...txtLike.map(a => normalizeAnswer(a, target, 'TXT')));
  }

  const rcode = typeof json.Status === 'number' ? json.Status : 0;
  const rcodeMessage = RCODE_MESSAGES[rcode];

  return {
    type,
    success: rcode === 0,
    records,
    count: records.length,
    error: rcode === 0 ? null : rcodeMessage,
    errorCode: rcode === 0 ? null : `RCODE_${rcode}`,
    authoritative: Boolean(json.AA),
    truncated: Boolean(json.TC),
    recursionAvailable: Boolean(json.RA),
    provider: response.provider,
    ttl: ttlFromAnswers(records),
    durationMs: 0
  };
}

/**
 * Resolve a single record type (with TTL) for a hostname.
 */
async function resolveRecordType(domain, type) {
  const startedAt = Date.now();
  const normalizedType = String(type || '').toUpperCase();

  if (!RECORD_TYPES.includes(normalizedType)) {
    return {
      type: normalizedType,
      success: false,
      records: [],
      count: 0,
      error: `Unsupported record type: ${normalizedType}`,
      errorCode: 'UNSUPPORTED_TYPE',
      durationMs: 0
    };
  }

  const cacheKey = `dns:${domain}:${normalizedType}`;
  const cachedResult = dnsCache.get(cacheKey);
  if (cachedResult) {
    return { ...cachedResult, durationMs: Date.now() - startedAt, fromCache: true };
  }

  let result;

  if (normalizedType === 'SRV') {
    const results = await Promise.all(
      COMMON_SRV_PREFIXES.map(prefix => queryNameType(domain, 'SRV', { queryName: `${prefix}.${domain}` }))
    );
    const records = results.flatMap(r => r.records);
    result = {
      type: 'SRV',
      success: true,
      records,
      count: records.length,
      error: null,
      errorCode: null,
      ttl: records.length ? Math.min(...records.map(r => r.ttl).filter(Boolean)) : null,
      durationMs: 0
    };
  } else if (normalizedType === 'TLSA') {
    const results = await Promise.all(
      COMMON_TLSA_PORTS.map(prefix => queryNameType(domain, 'TLSA', { queryName: `${prefix}.${domain}` }))
    );
    const records = results.flatMap(r => r.records);
    result = {
      type: 'TLSA',
      success: true,
      records,
      count: records.length,
      error: null,
      errorCode: null,
      ttl: records.length ? Math.min(...records.map(r => r.ttl).filter(Boolean)) : null,
      durationMs: 0
    };
  } else {
    result = await queryNameType(domain, normalizedType);
  }

  const cacheTtlMs = result.count > 0 && result.ttl
    ? Math.min(result.ttl * 1000, DNS_CACHE_TTL_MS)
    : 60 * 1000;

  dnsCache.set(cacheKey, result, cacheTtlMs);

  return { ...result, durationMs: Date.now() - startedAt, fromCache: false };
}

/**
 * Look up SPF, DMARC and DKIM policy details.
 */
async function resolveEmailAuthentication(domain) {
  const cacheKey = `email:${domain}`;
  const cachedEmail = dnsCache.get(cacheKey);
  if (cachedEmail) return cachedEmail;

  const [txtResult, dmarcResult] = await Promise.all([
    resolveRecordType(domain, 'TXT'),
    queryNameType(`_dmarc.${domain}`, 'TXT', { queryName: `_dmarc.${domain}` })
  ]);

  const txtRecords = txtResult.records || [];
  const spfRecord = txtRecords.find(r => r.subtype === 'SPF') || null;

  const dmarcRaw = (dmarcResult.records || []).map(r => r.value).find(v => /^v=DMARC1/i.test(v)) || null;
  let dmarc = { present: false, raw: null, policy: null, subdomainPolicy: null, percentage: null, reportingEmail: null, forensicEmail: null, tags: {} };

  if (dmarcRaw) {
    const tags = {};
    for (const part of dmarcRaw.split(';')) {
      const [k, v] = part.split('=').map(s => (s || '').trim());
      if (k && v !== undefined && v !== '') tags[k.toLowerCase()] = v;
    }
    dmarc = {
      present: true,
      raw: dmarcRaw,
      policy: (tags.p || 'none').toLowerCase(),
      subdomainPolicy: (tags.sp || tags.p || 'none').toLowerCase(),
      percentage: tags.pct || '100',
      reportingEmail: tags.rua || null,
      forensicEmail: tags.ruf || null,
      tags
    };
  }

  const selectorRecords = [];
  const selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim'];
  const selectorResults = await Promise.all(
    selectors.map(async selector => {
      const res = await queryNameType(`${selector}._domainkey.${domain}`, 'TXT', {
        queryName: `${selector}._domainkey.${domain}`
      });
      return (res.records || [])
        .filter(r => /v=DKIM1|k=|p=/.test(r.value))
        .map(r => ({ selector, value: r.value, ttl: r.ttl }));
    })
  );
  selectorResults.forEach(list => selectorRecords.push(...list));

  const emailAuth = {
    spf: spfRecord
      ? {
          present: true,
          raw: spfRecord.value,
          qualifier: /-all/.test(spfRecord.value) ? 'fail' : /~all/.test(spfRecord.value) ? 'softfail' : /\+all/.test(spfRecord.value) ? 'pass' : 'neutral',
          dnsLookups: (spfRecord.value.match(/\b(include|a|mx|ptr|exists|redirect)\b/g) || []).length
        }
      : { present: false, raw: null, qualifier: null, dnsLookups: 0 },
    dmarc,
    dkim: { present: selectorRecords.length > 0, records: selectorRecords }
  };

  dnsCache.set(cacheKey, emailAuth, DNS_CACHE_TTL_MS);
  return emailAuth;
}

/**
 * DNSSEC validation state via DoH AD flag and DS/DNSKEY presence.
 */
async function resolveDnssec(domain) {
  const cacheKey = `dnssec:${domain}`;
  const cachedDnssec = dnsCache.get(cacheKey);
  if (cachedDnssec) return cachedDnssec;

  try {
    const { json } = await dohQuery(domain, 'DS', { timeoutMs: QUERY_TIMEOUT_MS });
    const dsAnswers = (json.Answer || []).filter(a => a.type === 43);
    const dnskeys = await dohQuery(domain, 'DNSKEY', { timeoutMs: QUERY_TIMEOUT_MS });
    const dnskeyAnswers = (dnskeys.json.Answer || []).filter(a => a.type === 48);

    const result = {
      dnssecSupported: dsAnswers.length > 0 || dnskeyAnswers.length > 0,
      authenticatedData: Boolean(json.AD),
      dsRecords: dsAnswers,
      dnskeys: dnskeyAnswers,
      provider: dnskeys.provider
    };

    dnsCache.set(cacheKey, result, DNS_CACHE_TTL_MS);
    return result;
  } catch (_) {
    return { dnssecSupported: false, authenticatedData: false, dsRecords: [], dnskeys: [] };
  }
}

/**
 * Determine redirect/alias chain for the apex host.
 */
async function resolveChain(domain) {
  const chain = [];
  let current = domain;

  for (let depth = 0; depth < 6; depth++) {
    const res = await queryNameType(current, 'CNAME');
    if (!res.records.length) break;
    const next = res.records[0].value;
    if (!next || chain.includes(next)) break;
    chain.push(next);
    current = next;
  }

  return chain;
}

function buildHealthChecks({ recordsByType, dnssec, email }) {
  const checks = [];
  const aRecords = recordsByType.A?.records || [];
  const aaaaRecords = recordsByType.AAAA?.records || [];
  const nsRecords = recordsByType.NS?.records || [];
  const mxRecords = recordsByType.MX?.records || [];
  const caaRecords = recordsByType.CAA?.records || [];
  const httpsRecords = recordsByType.HTTPS?.records || [];

  checks.push(
    aRecords.length
      ? { id: 'a_record', category: 'Connectivity', status: 'pass', title: 'IPv4 Address Configured', description: `Domain resolves to ${aRecords.length} IPv4 address(es).` }
      : { id: 'a_record', category: 'Connectivity', status: 'warning', title: 'No IPv4 (A) Records Found', description: 'The apex domain does not return direct IPv4 A records.' }
  );

  checks.push(
    aaaaRecords.length
      ? { id: 'ipv6_record', category: 'Connectivity', status: 'pass', title: 'IPv6 (AAAA) Ready', description: `Domain has modern IPv6 address support (${aaaaRecords.length} record(s)).` }
      : { id: 'ipv6_record', category: 'Connectivity', status: 'info', title: 'IPv6 (AAAA) Not Configured', description: 'Optional but recommended for modern dual-stack networking.' }
  );

  if (nsRecords.length >= 2) {
    checks.push({ id: 'ns_redundancy', category: 'Reliability', status: 'pass', title: 'Nameserver Redundancy High', description: `Configured with ${nsRecords.length} authoritative nameservers.` });
  } else if (nsRecords.length === 1) {
    checks.push({ id: 'ns_redundancy', category: 'Reliability', status: 'warning', title: 'Single Point of Failure Nameserver', description: 'Only 1 nameserver found. Best practice requires at least 2 geographically distributed NS.' });
  } else {
    checks.push({ id: 'ns_redundancy', category: 'Reliability', status: 'fail', title: 'No Nameservers Found', description: 'No authoritative nameservers resolved.' });
  }

  checks.push(
    mxRecords.length
      ? { id: 'mx_record', category: 'Email', status: 'pass', title: 'Mail Servers (MX) Configured', description: `${mxRecords.length} mail exchange server(s) configured.` }
      : { id: 'mx_record', category: 'Email', status: 'info', title: 'No MX Records Found', description: 'Domain cannot receive email directly on the apex domain.' }
  );

  const spf = email.spf;
  if (spf.present) {
    const isStrict = spf.qualifier === 'fail';
    checks.push({
      id: 'spf_record',
      category: 'Security',
      status: isStrict ? 'pass' : 'warning',
      title: 'SPF Record Active',
      description: `SPF qualifier is '${spf.qualifier}' (${spf.dnsLookups} DNS lookup mechanism(s)).${spf.dnsLookups > 10 ? ' Exceeds the RFC 7208 limit of 10.' : ''}`
    });
  } else {
    checks.push({ id: 'spf_record', category: 'Security', status: mxRecords.length ? 'warning' : 'info', title: 'No SPF Record Found', description: 'Without SPF, spammers can spoof your domain email.' });
  }

  if (email.dmarc.present) {
    const isStrict = ['reject', 'quarantine'].includes(email.dmarc.policy);
    checks.push({
      id: 'dmarc_record',
      category: 'Security',
      status: isStrict ? 'pass' : 'warning',
      title: `DMARC Active (Policy: ${email.dmarc.policy})`,
      description: `DMARC protection is enabled with policy '${email.dmarc.policy}' (pct: ${email.dmarc.percentage}%).`
    });
  } else {
    checks.push({ id: 'dmarc_record', category: 'Security', status: mxRecords.length ? 'warning' : 'info', title: 'DMARC Record Missing', description: 'Domain has no _dmarc TXT policy published to protect against email spoofing.' });
  }

  checks.push(
    email.dkim.present
      ? { id: 'dkim_record', category: 'Email', status: 'pass', title: 'DKIM Selector Discovered', description: `DKIM public key found for selector(s): ${[...new Set(email.dkim.records.map(r => r.selector))].join(', ')}.` }
      : { id: 'dkim_record', category: 'Email', status: 'info', title: 'DKIM Selector Not Detected', description: 'No DKIM key found on common selectors; the real selector may be custom or unlisted.' }
  );

  checks.push(
    dnssec.dnssecSupported
      ? { id: 'dnssec', category: 'Security', status: 'pass', title: 'DNSSEC Signed & Secured', description: `Delegation signing keys published (${dnssec.dsRecords.length} DS record(s))${dnssec.authenticatedData ? ' and validator confirmed authenticity (AD flag set)' : ''}.` }
      : { id: 'dnssec', category: 'Security', status: 'info', title: 'DNSSEC Not Enabled', description: 'DNS responses are not cryptographically signed with DNSSEC.' }
  );

  checks.push(
    caaRecords.length
      ? { id: 'caa_record', category: 'Security', status: 'pass', title: 'CAA Certificate Authorization Present', description: `Only authorized CAs can issue SSL certificates (${caaRecords.length} rule(s)).` }
      : { id: 'caa_record', category: 'Security', status: 'info', title: 'No CAA Records', description: 'Any public Certificate Authority is permitted to issue certificates for this domain.' }
  );

  checks.push(
    httpsRecords.length
      ? { id: 'https_rr', category: 'Connectivity', status: 'pass', title: 'HTTPS/SVCB Record Published', description: 'Modern HTTPS service binding records are present (ALPN, ECH or HTTP/3 hints).' }
      : { id: 'https_rr', category: 'Connectivity', status: 'info', title: 'No HTTPS (SVCB) Record', description: 'Optional record that can advertise HTTP/3 and encrypted client hello support.' }
  );

  return checks;
}

/**
 * Comprehensive DNS resolution across all supported record types.
 */
async function lookupAllDns(inputDomain) {
  const startedAt = Date.now();
  const domain = String(inputDomain || '').replace(/\.$/, '').toLowerCase();

  const [recordResults, email, dnssec] = await Promise.all([
    Promise.all(RECORD_TYPES.map(type => resolveRecordType(domain, type))),
    resolveEmailAuthentication(domain),
    resolveDnssec(domain)
  ]);

  const recordsByType = {};
  let totalRecords = 0;
  for (const res of recordResults) {
    recordsByType[res.type] = res;
    totalRecords += res.count;
  }

  const healthChecks = buildHealthChecks({ recordsByType, dnssec, email });

  return {
    domain,
    recordsByType,
    totalRecords,
    recordTypesSupported: RECORD_TYPES,
    email,
    dmarc: email.dmarc,
    spf: email.spf,
    dkim: email.dkim,
    dnssec,
    healthChecks,
    durationMs: Date.now() - startedAt,
    fromCache: recordResults.every(r => r.fromCache)
  };
}

async function resolveChainSafe(domain) {
  const cacheKey = `chain:${domain}`;
  const cachedChain = dnsCache.get(cacheKey);
  if (cachedChain) return cachedChain;

  try {
    const chain = await resolveChain(domain);
    dnsCache.set(cacheKey, chain, DNS_CACHE_TTL_MS);
    return chain;
  } catch (_) {
    return [];
  }
}

module.exports = {
  lookupAllDns,
  resolveRecordType,
  resolveEmailAuthentication,
  resolveDnssec,
  resolveChain: resolveChainSafe,
  RECORD_TYPES,
  dnsCache,
  stripTrailingDot
};
