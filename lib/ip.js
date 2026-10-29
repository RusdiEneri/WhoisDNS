const dns = require('dns').promises;
const net = require('net');
const { TtlCache } = require('./cache');

const ipCache = new TtlCache({ max: 1000, ttlMs: 30 * 60 * 1000, name: 'ip' });
const IP_CACHE_TTL_MS = 30 * 60 * 1000;

function isIpAddress(str) {
  return typeof str === 'string' && net.isIP(str.trim()) !== 0;
}

async function lookupPtr(ip) {
  try {
    return await dns.reverse(ip);
  } catch (_) {
    return [];
  }
}

async function fetchGeo(ip) {
  try {
    const res = await fetch(
      `https://ipwho.is/${encodeURIComponent(ip)}?fields=success,message,country,country_code,region,city,latitude,longitude,timezone,connection`,
      { signal: AbortSignal.timeout(4000) }
    );
    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        return {
          country: data.country || null,
          countryCode: data.country_code || null,
          city: data.city || null,
          region: data.region || null,
          isp: data.connection?.isp || data.connection?.org || null,
          org: data.connection?.org || null,
          asn: data.connection?.asn ? `AS${data.connection.asn} ${data.connection.org || ''}`.trim() : null,
          lat: data.latitude ?? null,
          lon: data.longitude ?? null,
          timezone: data.timezone?.id || null
        };
      }
    }
  } catch (_) {}

  try {
    const res = await fetch(
      `https://api.iplocation.net/?ip=${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout(4000) }
    );
    if (res.ok) {
      const data = await res.json();
      return {
        country: data.country_name || null,
        countryCode: data.country_code2 || null,
        city: null,
        region: null,
        isp: data.isp || null,
        org: null,
        asn: null,
        lat: null,
        lon: null,
        timezone: null
      };
    }
  } catch (_) {}

  return {
    country: null, countryCode: null, city: null, region: null,
    isp: null, org: null, asn: null, lat: null, lon: null, timezone: null
  };
}

/**
 * Lookup IP geolocation, ASN and reverse DNS.
 */
async function lookupIpInfo(ip) {
  const cleanIp = String(ip || '').trim();
  if (!isIpAddress(cleanIp)) {
    const err = new Error('Invalid IP address.');
    err.statusCode = 400;
    throw err;
  }

  const cachedValue = ipCache.get(cleanIp);
  if (cachedValue) return { ...cachedValue, fromCache: true };

  const [geo, hostnames] = await Promise.all([fetchGeo(cleanIp), lookupPtr(cleanIp)]);

  const result = {
    ip: cleanIp,
    version: net.isIPv6(cleanIp) ? 6 : 4,
    ...geo,
    reverseDns: hostnames,
    primaryHostname: hostnames[0] || null,
    fromCache: false
  };

  ipCache.set(cleanIp, result, IP_CACHE_TTL_MS);
  return result;
}

module.exports = {
  isIpAddress,
  lookupPtr,
  lookupIpInfo,
  ipCache
};
