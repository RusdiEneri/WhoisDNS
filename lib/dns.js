const dns = require('dns').promises;

/**
 * Standard DNS record types supported
 */
const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'SRV'];

/**
 * Common SRV prefixes to check
 */
const COMMON_SRV_PREFIXES = [
  '_autodiscover._tcp',
  '_sip._tls',
  '_sip._tcp',
  '_xmpp-server._tcp',
  '_submission._tcp'
];

/**
 * Query DNS records with TTL using native Node DNS
 */
async function resolveRecordType(domain, type) {
  const startTime = Date.now();
  try {
    let records = [];
    switch (type) {
      case 'A': {
        const res = await dns.resolve4(domain, { ttl: true });
        records = res.map(r => ({
          type: 'A',
          value: r.address,
          ttl: r.ttl,
          raw: r
        }));
        break;
      }
      case 'AAAA': {
        const res = await dns.resolve6(domain, { ttl: true });
        records = res.map(r => ({
          type: 'AAAA',
          value: r.address,
          ttl: r.ttl,
          raw: r
        }));
        break;
      }
      case 'CNAME': {
        const res = await dns.resolveCname(domain);
        records = res.map(cname => ({
          type: 'CNAME',
          value: cname,
          ttl: null
        }));
        break;
      }
      case 'MX': {
        const res = await dns.resolveMx(domain);
        // Sort by priority ascending
        res.sort((a, b) => a.priority - b.priority);
        records = res.map(mx => ({
          type: 'MX',
          exchange: mx.exchange,
          priority: mx.priority,
          value: `${mx.exchange} (Priority: ${mx.priority})`,
          ttl: null
        }));
        break;
      }
      case 'TXT': {
        const res = await dns.resolveTxt(domain);
        records = res.map(chunks => {
          const joined = chunks.join('');
          let subtype = 'General';
          if (joined.startsWith('v=spf1')) subtype = 'SPF';
          else if (joined.includes('google-site-verification')) subtype = 'Google Verification';
          else if (joined.includes('MS=') || joined.includes('v=ms')) subtype = 'Microsoft Verification';
          else if (joined.includes('apple-domain-verification')) subtype = 'Apple Verification';
          else if (joined.includes('facebook-domain-verification')) subtype = 'Facebook Verification';
          else if (joined.includes('v=DMARC1')) subtype = 'DMARC';

          return {
            type: 'TXT',
            subtype,
            value: joined,
            ttl: null
          };
        });
        break;
      }
      case 'NS': {
        const res = await dns.resolveNs(domain);
        records = res.map(ns => ({
          type: 'NS',
          value: ns.toLowerCase(),
          ttl: null
        }));
        break;
      }
      case 'SOA': {
        const res = await dns.resolveSoa(domain);
        records = [{
          type: 'SOA',
          nsname: res.nsname,
          hostmaster: res.hostmaster,
          serial: res.serial,
          refresh: res.refresh,
          retry: res.retry,
          expire: res.expire,
          minttl: res.minttl,
          value: `Primary: ${res.nsname} | Admin: ${res.hostmaster} | Serial: ${res.serial}`,
          ttl: res.minttl
        }];
        break;
      }
      case 'CAA': {
        const res = await dns.resolveCaa(domain);
        records = res.map(caa => ({
          type: 'CAA',
          tag: caa.tag || (caa.issue ? 'issue' : caa.issuewild ? 'issuewild' : caa.iodef ? 'iodef' : 'unknown'),
          value: caa.value || caa.issue || caa.issuewild || caa.iodef,
          critical: caa.critical || 0,
          ttl: null
        }));
        break;
      }
      case 'SRV': {
        // Query common SRV prefixes concurrently
        const srvPromises = COMMON_SRV_PREFIXES.map(async prefix => {
          try {
            const srvRes = await dns.resolveSrv(`${prefix}.${domain}`);
            return srvRes.map(s => ({
              type: 'SRV',
              prefix,
              name: s.name,
              port: s.port,
              priority: s.priority,
              weight: s.weight,
              value: `${s.name}:${s.port} (Pri: ${s.priority}, Wgt: ${s.weight})`,
              ttl: null
            }));
          } catch (_) {
            return [];
          }
        });
        const srvResults = await Promise.all(srvPromises);
        records = srvResults.flat();
        break;
      }
      default:
        break;
    }

    return {
      type,
      success: true,
      records,
      count: records.length,
      durationMs: Date.now() - startTime
    };
  } catch (err) {
    // If ENOTFOUND or ENODATA, it simply means no record of this type exists
    const isNotFound = ['ENODATA', 'ENOTFOUND', 'ESERVFAIL', 'EREFUSED'].includes(err.code);
    return {
      type,
      success: !isNotFound,
      records: [],
      count: 0,
      error: isNotFound ? null : err.message,
      errorCode: err.code || 'ERROR',
      durationMs: Date.now() - startTime
    };
  }
}

/**
 * Query DMARC record (_dmarc.domain.com)
 */
async function resolveDmarc(domain) {
  try {
    const res = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = res.map(chunks => chunks.join('')).filter(txt => txt.startsWith('v=DMARC1'));
    if (flat.length > 0) {
      const dmarcStr = flat[0];
      const tags = {};
      dmarcStr.split(';').forEach(part => {
        const [k, v] = part.trim().split('=');
        if (k && v) tags[k.trim()] = v.trim();
      });

      return {
        present: true,
        raw: dmarcStr,
        policy: tags.p || 'none',
        subdomainPolicy: tags.sp || tags.p || 'none',
        percentage: tags.pct || '100',
        reportingEmail: tags.rua || null,
        forensicEmail: tags.ruf || null,
        tags
      };
    }
  } catch (_) {}

  return {
    present: false,
    raw: null,
    policy: null,
    subdomainPolicy: null
  };
}

/**
 * Query DNSSEC status via Cloudflare DoH
 */
async function resolveDnssec(domain) {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DS`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: AbortSignal.timeout(5000)
    });
    if (res.ok) {
      const json = await res.json();
      const hasDs = Array.isArray(json.Answer) && json.Answer.some(a => a.type === 43); // 43 is DS record
      return {
        dnssecSupported: hasDs,
        adFlag: json.AD || false, // Authenticated Data flag
        dsRecords: json.Answer || []
      };
    }
  } catch (_) {}

  return {
    dnssecSupported: false,
    adFlag: false,
    dsRecords: []
  };
}

/**
 * Comprehensive DNS resolution across all record types
 */
async function lookupAllDns(domain) {
  const startTime = Date.now();
  
  // Concurrently resolve all primary record types + DMARC + DNSSEC
  const recordPromises = RECORD_TYPES.map(type => resolveRecordType(domain, type));
  const dmarcPromise = resolveDmarc(domain);
  const dnssecPromise = resolveDnssec(domain);

  const [recordResults, dmarcResult, dnssecResult] = await Promise.all([
    Promise.all(recordPromises),
    dmarcPromise,
    dnssecPromise
  ]);

  // Aggregate results by record type
  const recordsByType = {};
  let totalRecords = 0;

  recordResults.forEach(res => {
    recordsByType[res.type] = res;
    totalRecords += res.count;
  });

  // Evaluate Health & Security Best Practices
  const healthChecks = [];

  // 1. IPv4 / A Record
  const aRecords = recordsByType['A']?.records || [];
  if (aRecords.length > 0) {
    healthChecks.push({
      id: 'a_record',
      category: 'Connectivity',
      status: 'pass',
      title: 'IPv4 Address Configured',
      description: `Domain resolves to ${aRecords.length} IPv4 address(es).`
    });
  } else {
    healthChecks.push({
      id: 'a_record',
      category: 'Connectivity',
      status: 'warning',
      title: 'No IPv4 (A) Records Found',
      description: 'The root domain does not return direct IPv4 A records.'
    });
  }

  // 2. IPv6 / AAAA Record
  const aaaaRecords = recordsByType['AAAA']?.records || [];
  if (aaaaRecords.length > 0) {
    healthChecks.push({
      id: 'ipv6_record',
      category: 'Connectivity',
      status: 'pass',
      title: 'IPv6 (AAAA) Ready',
      description: `Domain has modern IPv6 address support (${aaaaRecords.length} record(s)).`
    });
  } else {
    healthChecks.push({
      id: 'ipv6_record',
      category: 'Connectivity',
      status: 'info',
      title: 'IPv6 (AAAA) Not Configured',
      description: 'Optional but recommended for modern dual-stack networking.'
    });
  }

  // 3. Name Server Redundancy
  const nsRecords = recordsByType['NS']?.records || [];
  if (nsRecords.length >= 2) {
    healthChecks.push({
      id: 'ns_redundancy',
      category: 'Reliability',
      status: 'pass',
      title: 'Nameserver Redundancy High',
      description: `Configured with ${nsRecords.length} authoritative nameservers.`
    });
  } else if (nsRecords.length === 1) {
    healthChecks.push({
      id: 'ns_redundancy',
      category: 'Reliability',
      status: 'warning',
      title: 'Single Point of Failure Nameserver',
      description: 'Only 1 nameserver found. Best practice requires at least 2 geographically distributed NS.'
    });
  } else {
    healthChecks.push({
      id: 'ns_redundancy',
      category: 'Reliability',
      status: 'fail',
      title: 'No Nameservers Found',
      description: 'No authoritative nameservers resolved.'
    });
  }

  // 4. Mail Exchange (MX)
  const mxRecords = recordsByType['MX']?.records || [];
  if (mxRecords.length > 0) {
    healthChecks.push({
      id: 'mx_record',
      category: 'Email',
      status: 'pass',
      title: 'Mail Servers (MX) Configured',
      description: `${mxRecords.length} mail exchange server(s) configured.`
    });
  } else {
    healthChecks.push({
      id: 'mx_record',
      category: 'Email',
      status: 'info',
      title: 'No MX Records Found',
      description: 'Domain cannot receive email directly on apex domain.'
    });
  }

  // 5. SPF (Sender Policy Framework)
  const txtRecords = recordsByType['TXT']?.records || [];
  const spfRecord = txtRecords.find(t => t.subtype === 'SPF');
  if (spfRecord) {
    const isHardFail = spfRecord.value.includes('-all');
    const isSoftFail = spfRecord.value.includes('~all');
    healthChecks.push({
      id: 'spf_record',
      category: 'Security',
      status: 'pass',
      title: 'SPF Record Active',
      description: `Valid SPF record found: ${isHardFail ? 'Strict (-all)' : isSoftFail ? 'SoftFail (~all)' : 'Permissive'}.`
    });
  } else {
    healthChecks.push({
      id: 'spf_record',
      category: 'Security',
      status: mxRecords.length > 0 ? 'warning' : 'info',
      title: 'No SPF Record Found',
      description: 'Without SPF, spammers can spoof your domain email.'
    });
  }

  // 6. DMARC
  if (dmarcResult.present) {
    const isStrict = dmarcResult.policy === 'reject' || dmarcResult.policy === 'quarantine';
    healthChecks.push({
      id: 'dmarc_record',
      category: 'Security',
      status: isStrict ? 'pass' : 'warning',
      title: `DMARC Active (Policy: ${dmarcResult.policy})`,
      description: `DMARC protection is enabled with policy '${dmarcResult.policy}' (pct: ${dmarcResult.percentage}%).`
    });
  } else {
    healthChecks.push({
      id: 'dmarc_record',
      category: 'Security',
      status: mxRecords.length > 0 ? 'warning' : 'info',
      title: 'DMARC Record Missing',
      description: 'Domain has no _dmarc TXT policy published to protect against email spoofing.'
    });
  }

  // 7. DNSSEC
  if (dnssecResult.dnssecSupported) {
    healthChecks.push({
      id: 'dnssec',
      category: 'Security',
      status: 'pass',
      title: 'DNSSEC Signed & Secured',
      description: 'Domain has valid DS delegation records protecting against DNS cache poisoning.'
    });
  } else {
    healthChecks.push({
      id: 'dnssec',
      category: 'Security',
      status: 'info',
      title: 'DNSSEC Not Enabled',
      description: 'DNS responses are not cryptographically signed with DNSSEC.'
    });
  }

  // 8. CAA Record
  const caaRecords = recordsByType['CAA']?.records || [];
  if (caaRecords.length > 0) {
    healthChecks.push({
      id: 'caa_record',
      category: 'Security',
      status: 'pass',
      title: 'CAA Certificate Authorization Present',
      description: `Only authorized CAs can issue SSL certificates (${caaRecords.length} rule(s)).`
    });
  } else {
    healthChecks.push({
      id: 'caa_record',
      category: 'Security',
      status: 'info',
      title: 'No CAA Records',
      description: 'Any public Certificate Authority is permitted to issue certificates for this domain.'
    });
  }

  return {
    domain,
    recordsByType,
    totalRecords,
    dmarc: dmarcResult,
    dnssec: dnssecResult,
    healthChecks,
    durationMs: Date.now() - startTime
  };
}

module.exports = {
  lookupAllDns,
  resolveRecordType,
  resolveDmarc,
  resolveDnssec,
  RECORD_TYPES
};
