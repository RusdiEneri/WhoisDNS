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

test('SPA fallback serves HTML for client routes', async () => {
  const { status, contentType } = await get('/some/client/route');
  assert.equal(status, 200);
  assert.match(contentType, /text\/html/);
});

test('security headers are present', async () => {
  const { headers } = await get('/api/health');
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.ok(headers.get('content-security-policy'));
  assert.equal(headers.get('x-powered-by'), null);
});
