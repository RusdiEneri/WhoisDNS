const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeInput, cleanDomain, normalizeInput } = require('../lib/domain');
const { parseWhois } = require('../lib/whois');
const { normalizeAnswer, unquoteTxt } = require('../lib/doh');
const { TtlCache, cached } = require('../lib/cache');
const { RateLimiter } = require('../lib/ratelimit');

test('analyzeInput accepts a plain registrable domain', () => {
  const result = analyzeInput('example.com');
  assert.equal(result.ok, true);
  assert.equal(result.host, 'example.com');
  assert.equal(result.registrable, 'example.com');
  assert.equal(result.publicSuffix, 'com');
  assert.equal(result.isSubdomain, false);
});

test('analyzeInput extracts eTLD+1 from deep subdomains', () => {
  const result = analyzeInput('sub.mail.google.com');
  assert.equal(result.ok, true);
  assert.equal(result.host, 'sub.mail.google.com');
  assert.equal(result.registrable, 'google.com');
  assert.equal(result.isSubdomain, true);
});

test('analyzeInput understands multi-label public suffixes', () => {
  assert.equal(analyzeInput('domain.co.id').registrable, 'domain.co.id');
  assert.equal(analyzeInput('a.b.domain.web.id').registrable, 'domain.web.id');
  assert.equal(analyzeInput('shop.example.com.au').registrable, 'example.com.au');
});

test('analyzeInput strips protocols, paths, credentials and ports', () => {
  assert.equal(analyzeInput('https://user:pass@www.Example.COM:8443/a/b?x=1#f').host, 'www.example.com');
  assert.equal(analyzeInput('https://user:pass@www.Example.COM:8443/a/b?x=1#f').registrable, 'example.com');
  assert.equal(analyzeInput('  EXAMPLE.com.  ').host, 'example.com');
});

test('analyzeInput rejects invalid and dangerous input', () => {
  for (const bad of ['', '   ', 'foo', 'localhost', 'a..b.com', '-bad.com', 'bad-.com', 'co.id']) {
    assert.equal(analyzeInput(bad).ok, false, `expected rejection for ${JSON.stringify(bad)}`);
  }
});

test('analyzeInput neutralizes newline injection attempts', () => {
  const result = analyzeInput('example.com\r\nevil.com');
  assert.equal(result.host, 'example.comevil.com');
  assert.ok(!result.host.includes('\n') && !result.host.includes('\r'));
  assert.equal(normalizeInput('example.com\r\n-X').includes('\r'), false);
});

test('analyzeInput detects IP addresses', () => {
  assert.equal(analyzeInput('1.2.3.4').isIp, true);
  assert.equal(analyzeInput('2606:4700:4700::1111').isIp, true);
  assert.equal(analyzeInput('2606:4700:4700::1111').ipVersion, 6);
});

test('analyzeInput converts IDN to punycode', () => {
  const result = analyzeInput('münchen.de');
  assert.equal(result.ok, true);
  assert.equal(result.host, 'xn--mnchen-3ya.de');
  assert.equal(result.isIdn, true);
});

test('cleanDomain returns the registrable domain', () => {
  assert.equal(cleanDomain('mail.google.com'), 'google.com');
  assert.equal(cleanDomain('not a domain'), '');
});

test('parseWhois extracts structured fields', () => {
  const raw = [
    'Domain Name: EXAMPLE.COM',
    'Registry Domain ID: 2336799_DOMAIN_COM-VRSN',
    'Registrar WHOIS Server: whois.example-registrar.com',
    'Registrar: Example Registrar, Inc.',
    'Registrar IANA ID: 376',
    'Creation Date: 1995-08-14T04:00:00Z',
    'Registry Expiry Date: 2030-08-13T04:00:00Z',
    'Updated Date: 2024-08-14T07:01:34Z',
    'Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited',
    'Name Server: A.IANA-SERVERS.NET',
    'Name Server: B.IANA-SERVERS.NET',
    'DNSSEC: signedDelegation'
  ].join('\r\n');

  const parsed = parseWhois(raw, 'example.com');
  assert.equal(parsed.domainName, 'example.com');
  assert.equal(parsed.registrar, 'Example Registrar, Inc.');
  assert.equal(parsed.registrarIanaId, '376');
  assert.equal(parsed.creationDate, '1995-08-14T04:00:00Z');
  assert.equal(parsed.nameServers.length, 2);
  assert.deepEqual(parsed.status, ['clientTransferProhibited']);
  assert.equal(parsed.dnssec, 'signedDelegation');
  assert.equal(parsed.isAvailable, false);
  assert.match(parsed.domainAge, /years/);
  assert.ok(parsed.daysUntilExpiry > 0);
});

test('parseWhois flags available domains but not subdomain NXDOMAIN text', () => {
  assert.equal(parseWhois('No match for "FOO.COM".', 'foo.com').isAvailable, true);
  assert.equal(parseWhois('Domain Name: GOOGLE.COM\nRegistrar: MarkMonitor', 'google.com').isAvailable, false);
  assert.equal(parseWhois('', 'example.com').raw, '');
});

test('normalizeAnswer handles MX, TXT and SOA shapes', () => {
  const mx = normalizeAnswer({ data: '10 mail.example.com.', TTL: 300 }, 'example.com', 'MX');
  assert.equal(mx.priority, 10);
  assert.equal(mx.exchange, 'mail.example.com');
  assert.equal(mx.ttl, 300);

  const txt = normalizeAnswer({ data: '"v=spf1 -all"', TTL: 60 }, 'example.com', 'TXT');
  assert.equal(txt.value, 'v=spf1 -all');
  assert.equal(txt.subtype, 'SPF');

  const soa = normalizeAnswer({ data: 'ns1.example.com. hostmaster.example.com. 2024 7200 3600 1209600 3600', TTL: 900 }, 'example.com', 'SOA');
  assert.equal(soa.nsname, 'ns1.example.com');
  assert.equal(soa.hostmaster, 'hostmaster.example.com');
  assert.equal(soa.serial, 2024);
});

test('unquoteTxt joins multi-chunk TXT values', () => {
  assert.equal(unquoteTxt('"part one" "part two"'), 'part onepart two');
  assert.equal(unquoteTxt('"quote \\" inside"'), 'quote " inside');
});

test('TtlCache expires entries and reports hit rate', async () => {
  const cache = new TtlCache({ max: 2, ttlMs: 40 });
  cache.set('a', 1);
  assert.equal(cache.get('a'), 1);
  assert.equal(cache.get('missing'), undefined);
  await new Promise(r => setTimeout(r, 60));
  assert.equal(cache.get('a'), undefined);
  assert.equal(cache.stats().hitRate > 0, true);
});

test('TtlCache evicts oldest entry beyond capacity', () => {
  const cache = new TtlCache({ max: 2, ttlMs: 10_000 });
  cache.set('a', 1);
  cache.set('b', 2);
  cache.set('c', 3);
  assert.equal(cache.get('a'), undefined);
  assert.equal(cache.get('c'), 3);
  assert.equal(cache.stats().size, 2);
});

test('cached reuses producer output on second call', async () => {
  const cache = new TtlCache({ max: 10, ttlMs: 10_000 });
  let calls = 0;
  const producer = async () => { calls++; return { value: calls }; };

  const first = await cached(cache, 'k', producer);
  const second = await cached(cache, 'k', producer);

  assert.equal(first.cached, false);
  assert.equal(second.cached, true);
  assert.equal(calls, 1);
  assert.deepEqual(second.value, { value: 1 });
});

test('RateLimiter blocks requests past the limit', () => {
  const limiter = new RateLimiter({ windowMs: 60_000, max: 2 });
  assert.equal(limiter.consume('ip').allowed, true);
  assert.equal(limiter.consume('ip').allowed, true);
  const blocked = limiter.consume('ip');
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterSec >= 1);
  assert.equal(limiter.consume('other-ip').allowed, true);
});
