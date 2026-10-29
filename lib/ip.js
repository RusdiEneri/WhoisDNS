const dns = require('dns').promises;

/**
 * Validate IPv4 or IPv6
 */
function isIpAddress(str) {
  if (!str) return false;
  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Pattern = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;
  return ipv4Pattern.test(str) || ipv6Pattern.test(str);
}

/**
 * Reverse DNS PTR lookup
 */
async function lookupPtr(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames;
  } catch (err) {
    return [];
  }
}

/**
 * Lookup IP Geolocation and ASN information
 */
async function lookupIpInfo(ip) {
  const cleanIp = ip.trim();
  const ptrPromise = lookupPtr(cleanIp);

  let geoData = {
    ip: cleanIp,
    country: null,
    countryCode: null,
    city: null,
    region: null,
    isp: null,
    org: null,
    asn: null,
    lat: null,
    lon: null,
    flag: null
  };

  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(cleanIp)}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query`, {
      signal: AbortSignal.timeout(4000)
    });
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        geoData.country = data.country;
        geoData.countryCode = data.countryCode;
        geoData.city = data.city;
        geoData.region = data.regionName;
        geoData.isp = data.isp;
        geoData.org = data.org;
        geoData.asn = data.as;
        geoData.lat = data.lat;
        geoData.lon = data.lon;
        geoData.timezone = data.timezone;
      }
    }
  } catch (err) {
    // Attempt fallback
    try {
      const fb = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(cleanIp)}`, {
        signal: AbortSignal.timeout(4000)
      });
      if (fb.ok) {
        const d = await fb.json();
        geoData.country = d.countryName;
        geoData.countryCode = d.countryCode;
        geoData.city = d.cityName;
        geoData.region = d.regionName;
        geoData.lat = d.latitude;
        geoData.lon = d.longitude;
      }
    } catch (_) {}
  }

  const hostnames = await ptrPromise;
  geoData.reverseDns = hostnames;
  geoData.primaryHostname = hostnames[0] || null;

  return geoData;
}

module.exports = {
  isIpAddress,
  lookupPtr,
  lookupIpInfo
};
