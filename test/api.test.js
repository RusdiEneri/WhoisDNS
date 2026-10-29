const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../server');

let server;
let baseUrl;

test.before(async () => {
  await new Promise(resolve => {
    server = app.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

test.after(() => new Promise(resolve => server.close(resolve)));

async function get(path) {
  const res = await fetch(`${baseUrl}${path}`);
  const contentType = res.headers.get('content-type') || '';
  const body = contentType.includes('application/json') ? await res.json() : await res.text();
  return { status: res.status, body, headers: res.headers, contentType };
}

test('GET /api/health reports engine status', async () => {
  const { status, body } = await get('/api/health');
  assert.equal(status, 200);
  assert.equal(body.status, 'ok');
  assert.ok(Array.isArray(body.caches));
});

test('GET /api/whois without domain returns 400', async () => {
  const { status, body } = await get('/api/whois');
  assert.equal(status, 400);
  assert.match(body.error, /required/i);
});

test('GET /api/whois rejects invalid domain with 400, not 500', async () => {
  for (const bad of ['foo', 'localhost', 'a..b.com', '-bad.com']) {
    const { status, body } = await get(`/api/whois?domain=${encodeURIComponent(bad)}`);
    assert.equal(status, 400, `expected 400 for ${bad}`);
    assert.ok(body.error);
  }
});

test('GET /api/dns rejects unsupported record types', async () => {
  const { status, body } = await get('/api/dns?domain=example.com&type=BOGUS');
  assert.equal(status, 400);
  assert.ok(body.supportedTypes.includes('HTTPS'));
});

test('GET /api/propagation rejects unsupported record types', async () => {
  const { status, body } = await get('/api/propagation?domain=example.com&type=BOGUS');
  assert.equal(status, 400);
  assert.ok(Array.isArray(body.supportedTypes));
});

test('GET /api/ip rejects non-IP input', async () => {
  const { status, body } = await get('/api/ip?ip=not-an-ip');
  assert.equal(status, 400);
  assert.match(body.error, /invalid ip/i);
});

test('unknown /api route returns JSON 404, not the SPA shell', async () => {
  const { status, body, contentType } = await get('/api/nope');
  assert.equal(status, 404);
  assert.match(contentType, /application\/json/);
  assert.match(body.error, /unknown api endpoint/i);
});

test('static files are served from the public directory', async () => {
  const { status, contentType } = await get('/css/style.css');
  assert.equal(status, 200);
  assert.match(contentType, /text\/css/);
});

test('security headers are present', async () => {
  const { headers } = await get('/api/health');
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.ok(headers.get('content-security-policy'));
  assert.equal(headers.get('x-powered-by'), null);
});

test('robots.txt is served as plain text and points to the sitemap', async () => {
  const { status, body, headers } = await get('/robots.txt');
  assert.equal(status, 200);
  assert.match(headers.get('content-type'), /text\/plain/);
  assert.match(body, /User-agent: \*/);
  assert.match(body, /Disallow: \/api\//);
  assert.match(body, /Sitemap: https?:\/\/.+\/sitemap\.xml/);
});

test('sitemap.xml is valid XML referencing the site root', async () => {
  const { status, body, headers } = await get('/sitemap.xml');
  assert.equal(status, 200);
  assert.match(headers.get('content-type'), /xml/);
  assert.match(body, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.match(body, /<loc>https?:\/\/.+\/<\/loc>/);
  assert.match(body, /<lastmod>\d{4}-\d{2}-\d{2}<\/lastmod>/);
});

test('custom 404 page is served for unknown non-API routes', async () => {
  const { status, body, contentType } = await get('/this-page-does-not-exist');
  assert.equal(status, 404);
  assert.match(contentType, /text\/html/);
  assert.match(body, /Page not found/);
  assert.match(body, /noindex/);
});

test('favicon.svg is served with an image content type', async () => {
  const { status, contentType } = await get('/favicon.svg');
  assert.equal(status, 200);
  assert.match(contentType, /svg/);
});

test('web manifest is served', async () => {
  const res = await fetch(`${baseUrl}/site.webmanifest`);
  const body = await res.text();
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /json/);
  assert.equal(body.includes('WhoisDNS'), true);
});

test('filled honeypot field is rejected by the lookup endpoint', async () => {
  const { status, body } = await get('/api/lookup?domain=example.com&website=http://spam.test');
  assert.equal(status, 400);
  assert.equal(body.reason, 'honeypot');
});

test('instant form submission is rejected as bot-like', async () => {
  const { status, body } = await get(`/api/lookup?domain=example.com&form_ts=${Date.now()}`);
  assert.equal(status, 400);
  assert.equal(body.reason, 'submitted_too_fast');
});

test('homepage substitutes SITE_URL placeholders and keeps no template tokens', async () => {
  const { status, body } = await get('/');
  assert.equal(status, 200);
  assert.ok(!body.includes('{{SITE_URL}}'), 'template placeholder leaked to the client');
  assert.match(body, /<link rel="canonical" href="http:\/\/127\.0\.0\.1:\d+\/"/);
});

test('/index.html redirects permanently to /', async () => {
  const res = await fetch(`${baseUrl}/index.html`, { redirect: 'manual' });
  assert.equal(res.status, 301);
  assert.equal(res.headers.get('location'), '/');
});
