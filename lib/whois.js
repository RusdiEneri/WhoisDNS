const net = require('net');

// Cache IANA TLD servers in-memory for speed
const tldCache = new Map([
  ['com', 'whois.verisign-grs.com'],
  ['net', 'whois.verisign-grs.com'],
  ['org', 'whois.pir.org'],
  ['info', 'whois.afilias.net'],
  ['biz', 'whois.nic.biz'],
  ['io', 'whois.nic.io'],
  ['co', 'whois.nic.co'],
  ['id', 'whois.id'],
  ['me', 'whois.nic.me'],
  ['dev', 'whois.nic.google'],
  ['app', 'whois.nic.google'],
  ['xyz', 'whois.nic.xyz'],
  ['ai', 'whois.nic.ai'],
  ['uk', 'whois.nic.uk'],
  ['de', 'whois.denic.de'],
  ['nl', 'whois.domain-registry.nl'],
  ['eu', 'whois.eu'],
  ['fr', 'whois.nic.fr'],
  ['ca', 'whois.cira.ca'],
  ['au', 'whois.auda.org.au'],
  ['jp', 'whois.jprs.jp'],
  ['sg', 'whois.sgnic.sg'],
  ['my', 'whois.mynic.my'],
  ['in', 'whois.registry.in'],
  ['ru', 'whois.tcinet.ru'],
  ['br', 'whois.registro.br'],
  ['tech', 'whois.nic.tech'],
  ['online', 'whois.nic.online'],
  ['site', 'whois.nic.site'],
  ['store', 'whois.nic.store'],
  ['cloud', 'whois.nic.cloud']
]);

/**
 * Execute raw socket query to port 43 WHOIS server
 */
function querySocket(server, query, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let resolved = false;
    let data = '';

    // Handle special server query format if needed
    let formattedQuery = query.trim() + '\r\n';
    if (server === 'whois.denic.de') {
      formattedQuery = '-T dn,ace ' + formattedQuery;
    } else if (server === 'whois.jprs.jp') {
      formattedQuery = formattedQuery + '/e\r\n';
    }

    const client = net.createConnection({ host: server, port: 43, timeout: timeoutMs }, () => {
      client.write(formattedQuery);
    });

    client.setEncoding('utf8');

    client.on('data', chunk => {
      data += chunk;
      // Cap at 256KB to avoid memory bloat
      if (data.length > 262144) {
        client.destroy();
      }
    });

    client.on('timeout', () => {
      if (!resolved) {
        resolved = true;
        client.destroy();
        resolve(data.trim() ? data : `Error: Timeout connecting to ${server}`);
      }
    });

    client.on('end', () => {
      if (!resolved) {
        resolved = true;
        resolve(data);
      }
    });

    client.on('error', err => {
      if (!resolved) {
        resolved = true;
        reject(err);
      }
    });
  });
}

/**
 * Extract TLD from domain (handles multi-part like .co.id, .com.au)
 */
function getTld(domain) {
  const parts = domain.toLowerCase().trim().split('.');
  if (parts.length < 2) return '';
  if (parts.length >= 3) {
    const secondLevel = parts.slice(-2).join('.');
    if (['co.id', 'web.id', 'my.id', 'ac.id', 'go.id', 'sch.id', 'or.id', 'net.id', 'biz.id',
         'co.uk', 'org.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'com.sg', 'com.my'].includes(secondLevel)) {
      // For WHOIS server determination, the top-level is the last part
      return parts[parts.length - 1];
    }
  }
  return parts[parts.length - 1];
}

/**
 * Find authoritative WHOIS server for a TLD via IANA
 */
async function getTldWhoisServer(tld) {
  if (tldCache.has(tld)) {
    return tldCache.get(tld);
  }

  try {
    const ianaResponse = await querySocket('whois.iana.org', tld, 6000);
    const match = ianaResponse.match(/whois:\s*([^\s\r\n]+)/i);
    if (match && match[1]) {
      const server = match[1].trim();
      tldCache.set(tld, server);
      return server;
    }
  } catch (err) {
    console.warn(`IANA lookup failed for .${tld}:`, err.message);
  }

  // Fallback default
  return `whois.nic.${tld}`;
}

/**
 * Clean domain input (remove protocol, path, port, www)
 */
function cleanDomain(input) {
  if (!input) return '';
  let cleaned = input.trim().toLowerCase();
  cleaned = cleaned.replace(/^https?:\/\//i, '');
  cleaned = cleaned.replace(/^www\./i, '');
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split(':')[0];
  return cleaned;
}

/**
 * Parse raw WHOIS response text into structured data
 */
function parseWhois(rawText, domain) {
  const result = {
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
    registrant: {
      name: null,
      organization: null,
      country: null,
      state: null,
      email: null
    },
    isAvailable: false,
    raw: rawText
  };

  if (!rawText || typeof rawText !== 'string') {
    return result;
  }

  // Check availability indicators
  const notFoundPatterns = [
    /no match for/i,
    /not found/i,
    /domain not found/i,
    /no data found/i,
    /status:\s*free/i,
    /status:\s*available/i,
    /no object found/i,
    /object does not exist/i,
    /the queried object does not exist/i
  ];
  result.isAvailable = notFoundPatterns.some(p => p.test(rawText));

  const lines = rawText.split('\n');

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('%') || trimmed.startsWith('#')) return;

    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) return;

    const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const value = trimmed.slice(colonIdx + 1).trim();
    if (!value) return;

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
      result.registrarUrl = value;
    } else if (key === 'registrar abuse contact email') {
      result.registrarAbuseEmail = value;
    } else if (key === 'registrar abuse contact phone') {
      result.registrarAbusePhone = value;
    } else if (key === 'creation date' || key === 'created' || key === 'registration time' || key === 'registered on') {
      if (!result.creationDate) result.creationDate = value;
    } else if (key === 'registry expiry date' || key === 'registrar registration expiration date' || key === 'expiry date' || key === 'expiration date' || key === 'paid-till') {
      if (!result.expiryDate) result.expiryDate = value;
    } else if (key === 'updated date' || key === 'last updated' || key === 'last-update' || key === 'modified') {
      if (!result.updatedDate) result.updatedDate = value;
    } else if (key === 'domain status' || key === 'status') {
      const statusCode = value.split(' ')[0].trim();
      if (statusCode && !result.status.includes(statusCode)) {
        result.status.push(statusCode);
      }
    } else if (key === 'name server' || key === 'nserver' || key === 'nameservers') {
      const nsHost = value.split(' ')[0].toLowerCase().trim().replace(/\.$/, '');
      if (nsHost && !result.nameServers.includes(nsHost)) {
        result.nameServers.push(nsHost);
      }
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
  });

  // Calculate dates & age
  if (result.creationDate) {
    try {
      const created = new Date(result.creationDate);
      if (!isNaN(created.getTime())) {
        const now = new Date();
        const diffMs = now.getTime() - created.getTime();
        const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const years = (days / 365.25).toFixed(1);
        result.domainAge = `${years} years (${days.toLocaleString()} days)`;
      }
    } catch (_) {}
  }

  if (result.expiryDate) {
    try {
      const expires = new Date(result.expiryDate);
      if (!isNaN(expires.getTime())) {
        const now = new Date();
        const diffMs = expires.getTime() - now.getTime();
        const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        result.daysUntilExpiry = days;
      }
    } catch (_) {}
  }

  return result;
}

/**
 * Fallback to RDAP if socket fails
 */
async function queryRdap(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/rdap+json, application/json'
      },
      signal: AbortSignal.timeout(6000)
    });
    if (res.ok) {
      return await res.json();
    }
  } catch (err) {
    // ignore rdap failure
  }
  return null;
}

/**
 * Main WHOIS query function with multi-tier referral resolution
 */
async function lookupWhois(inputDomain) {
  const domain = cleanDomain(inputDomain);
  if (!domain) {
    throw new Error('Invalid domain name provided');
  }

  const tld = getTld(domain);
  if (!tld) {
    throw new Error('Unable to extract TLD from domain name');
  }

  let primaryServer = await getTldWhoisServer(tld);
  let rawText = '';

  try {
    rawText = await querySocket(primaryServer, domain, 7000);

    // Referral lookup for registrar whois (e.g. Verisign -> GoDaddy/MarkMonitor)
    const referralMatch = rawText.match(/Registrar WHOIS Server:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    if (referralMatch && referralMatch[1]) {
      const referralServer = referralMatch[1].trim();
      if (referralServer && referralServer !== primaryServer && referralServer.includes('.')) {
        try {
          const secondResponse = await querySocket(referralServer, domain, 7000);
          if (secondResponse && secondResponse.trim().length > 100) {
            rawText = rawText + '\n\n--- REGISTRAR WHOIS SERVER RESPONSE (' + referralServer + ') ---\n\n' + secondResponse;
          }
        } catch (subErr) {
          console.warn(`Referral query to ${referralServer} failed:`, subErr.message);
        }
      }
    }
  } catch (socketErr) {
    console.warn(`Socket WHOIS failed for ${domain} on ${primaryServer}:`, socketErr.message);
    
    // RDAP Fallback
    const rdapData = await queryRdap(domain);
    if (rdapData) {
      const rdapResult = {
        domainName: rdapData.ldhName || domain,
        registryDomainId: rdapData.handle || null,
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
        status: rdapData.status || [],
        nameServers: (rdapData.nameservers || []).map(ns => (ns.ldhName || '').toLowerCase()).filter(Boolean),
        dnssec: rdapData.secureDNS ? (rdapData.secureDNS.delegationSigned ? 'signed' : 'unsigned') : null,
        registrant: { name: null, organization: null, country: null, state: null, email: null },
        isAvailable: false,
        raw: JSON.stringify(rdapData, null, 2)
      };

      if (rdapData.events) {
        rdapData.events.forEach(e => {
          if (e.eventAction === 'registration') rdapResult.creationDate = e.eventDate;
          if (e.eventAction === 'expiration') rdapResult.expiryDate = e.eventDate;
          if (e.eventAction === 'last changed') rdapResult.updatedDate = e.eventDate;
        });
      }

      if (rdapData.entities) {
        rdapData.entities.forEach(ent => {
          if (ent.roles && ent.roles.includes('registrar')) {
            if (ent.vcardArray && ent.vcardArray[1]) {
              const fn = ent.vcardArray[1].find(item => item[0] === 'fn');
              if (fn) rdapResult.registrar = fn[3];
            }
          }
        });
      }

      return rdapResult;
    }

    throw new Error(`WHOIS query failed: ${socketErr.message}`);
  }

  return parseWhois(rawText, domain);
}

module.exports = {
  lookupWhois,
  cleanDomain,
  getTld
};
