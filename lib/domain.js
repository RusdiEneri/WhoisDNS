const net = require('net');
const { domainToASCII } = require('url');
const { parse: parseTld } = require('tldts');

const MAX_HOST_LENGTH = 253;
const LABEL_PATTERN = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

function invalid(reason, host) {
  return { ok: false, reason, host: host || null, isIp: false };
}

/**
 * Strip protocol, credentials, path and port from raw user input.
 * IP literals (v4/v6) are preserved because their colons are meaningful.
 */
function normalizeInput(raw) {
  if (typeof raw !== 'string') return '';

  let value = raw.replace(CONTROL_CHARS, '').trim();
  if (!value) return '';

  // Bracketed IPv6 literal, e.g. [2606:4700::1111]:443
  const bracketed = value.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) return bracketed[1].trim().toLowerCase();

  if (net.isIP(value)) return value.toLowerCase();

  const lower = value.toLowerCase();
  if (lower.startsWith('http://') || lower.startsWith('https://') || /^[a-z][a-z0-9+.-]*:\/\//.test(lower)) {
    value = lower.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  }

  value = value.split('#')[0].split('?')[0].split('/')[0];
  value = value.split('@').pop();

  // Bare IPv6 without brackets (contains 2+ colons and only hex/colon/dot)
  if (/^[0-9a-f:.]+$/i.test(value) && (value.match(/:/g) || []).length >= 2 && net.isIP(value)) {
    return value.toLowerCase();
  }

  value = value.split(':')[0];
  value = value.replace(/\.+$/, '');

  return value.toLowerCase();
}

/**
 * Convert a possibly-unicode hostname into ASCII (punycode) form.
 * Unicode characters are converted rather than silently deleted.
 */
function toAscii(value) {
  if (!value) return '';
  if (/^[\x20-\x7e]+$/.test(value)) return value;
  return domainToASCII(value);
}

/**
 * Validate and classify user input.
 * Returns the normalized host, its registrable domain (eTLD+1) and public suffix.
 */
function analyzeInput(raw) {
  const normalized = normalizeInput(raw);

  if (!normalized) return invalid('Domain is required.');
  if (normalized.length > MAX_HOST_LENGTH) {
    return invalid('Domain name exceeds 253 characters.', normalized);
  }

  if (net.isIP(normalized)) {
    return {
      ok: true,
      host: normalized,
      isIp: true,
      ipVersion: net.isIPv6(normalized) ? 6 : 4,
      registrable: normalized,
      publicSuffix: null,
      isSubdomain: false,
      tld: null,
      tldKnown: true,
      isIdn: false
    };
  }

  const asciiHost = toAscii(normalized);
  if (!asciiHost) return invalid('Invalid internationalized domain name.', normalized);
  if (asciiHost.length > MAX_HOST_LENGTH) {
    return invalid('Domain name exceeds 253 characters after IDN conversion.', normalized);
  }

  const labels = asciiHost.split('.');
  if (labels.length < 2) {
    return invalid('Enter a full domain name including its TLD (example.com).', normalized);
  }
  if (labels.length > 127) return invalid('Domain name has too many labels.', normalized);
  if (!labels.every(label => LABEL_PATTERN.test(label))) {
    return invalid('Domain contains an invalid label (bad characters or hyphen placement).', normalized);
  }

  const parsed = parseTld(asciiHost, { allowPrivateDomains: false });
  if (!parsed.domain) {
    return invalid('That is not a registrable domain (it is a public suffix or malformed).', normalized);
  }

  return {
    ok: true,
    host: asciiHost,
    isIp: false,
    ipVersion: null,
    registrable: parsed.domain,
    publicSuffix: parsed.publicSuffix,
    isSubdomain: asciiHost !== parsed.domain,
    tld: parsed.publicSuffix,
    tldKnown: Boolean(parsed.isIcann),
    isIdn: asciiHost !== normalized
  };
}

function cleanDomain(input) {
  const analyzed = analyzeInput(input);
  return analyzed.ok ? (analyzed.registrable || analyzed.host) : '';
}

module.exports = {
  analyzeInput,
  normalizeInput,
  cleanDomain,
  MAX_HOST_LENGTH
};
