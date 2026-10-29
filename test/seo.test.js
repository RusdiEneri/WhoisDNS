const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const INDEX = path.join(PUBLIC_DIR, 'index.html');

function readIndex() {
  return fs.readFileSync(INDEX, 'utf8');
}

test('internal asset references in index.html all exist on disk', () => {
  const html = readIndex();
  const refs = [...html.matchAll(/(?:href|src)="(\/(?!\/)[^"#?]*)(?:[?#][^"]*)?"/g)]
    .map(m => m[1])
    .filter(ref => !ref.startsWith('/api/'));
  const unique = [...new Set(refs)];
  assert.ok(unique.length > 0, 'expected at least one local asset reference');

  for (const ref of unique) {
    const filePath = path.join(PUBLIC_DIR, ref.replace(/^\//, ''));
    const exists = fs.existsSync(filePath) || fs.existsSync(filePath + '.html');
    assert.ok(exists, `missing referenced file: ${ref}`);
  }
});

test('index.html declares canonical, OG and Twitter metadata', () => {
  const html = readIndex();
  assert.match(html, /<link rel="canonical" href="(\{\{SITE_URL\}\}|https?:\/\/)[^"]*"/);
  assert.match(html, /<meta property="og:title"/);
  assert.match(html, /<meta property="og:image"/);
  assert.match(html, /<meta name="twitter:card"/);
  assert.match(html, /<meta name="robots" content="index, follow/);
});

test('structured data is valid JSON with Organization and WebApplication', () => {
  const html = readIndex();
  const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
  assert.ok(blocks.length >= 2, 'expected at least two JSON-LD blocks');

  const types = [];
  for (const block of blocks) {
    const parsed = JSON.parse(block[1]);
    const collect = node => {
      if (!node || typeof node !== 'object') return;
      if (node['@type']) {
        if (Array.isArray(node['@type'])) types.push(...node['@type']);
        else types.push(node['@type']);
      }
      if (Array.isArray(node['@graph'])) node['@graph'].forEach(collect);
    };
    collect(parsed);
  }

  assert.ok(types.includes('Organization'), 'Organization schema missing');
  assert.ok(types.includes('WebApplication'), 'WebApplication schema missing');
  assert.ok(types.includes('BreadcrumbList'), 'BreadcrumbList schema missing');
});

test('favicon, manifest and 404 page exist', () => {
  for (const file of ['favicon.svg', 'site.webmanifest', '404.html', 'og-image.svg']) {
    assert.ok(fs.existsSync(path.join(PUBLIC_DIR, file)), `missing ${file}`);
  }
});

test('breadcrumb navigation is present and linked to home', () => {
  const html = readIndex();
  assert.match(html, /<nav aria-label="Breadcrumb"/);
  assert.match(html, /aria-current="page"/);
});

test('footer contains internal links to tools and resources', () => {
  const html = readIndex();
  assert.match(html, /<nav class="footer-nav"/);
  const footerLinks = html.match(/<a href="\/[^"]*"/g) || [];
  assert.ok(footerLinks.length >= 4, `expected several internal footer links, found ${footerLinks.length}`);
});

test('anti-spam honeypots are hidden from assistive tech', () => {
  const html = readIndex();
  assert.match(html, /class="hp-field" aria-hidden="true"/);
  assert.match(html, /id="hp-website"/);
  assert.match(html, /id="form-ts"/);
});

test('form input has validation accessibility wiring', () => {
  const html = readIndex();
  assert.match(html, /aria-describedby="domain-error"/);
  assert.match(html, /id="domain-error" role="alert"/);
});

test('analytics script is loaded before the app script', () => {
  const html = readIndex();
  const trackIdx = html.indexOf('/js/track.js');
  const appIdx = html.indexOf('/js/app.js');
  assert.ok(trackIdx > -1, 'track.js not referenced');
  assert.ok(appIdx > trackIdx, 'track.js must load before app.js');
});

test('tracking hooks are wired to form submit and CTAs', () => {
  const app = fs.readFileSync(path.join(PUBLIC_DIR, 'js', 'app.js'), 'utf8');
  assert.match(app, /trackEvent\('form_submit'/);
  assert.match(app, /trackEvent\('cta_click'/);
  assert.match(app, /trackEvent\('form_invalid'/);
});

test('no leftover data: URI favicon (must be a real file now)', () => {
  const html = readIndex();
  assert.ok(!html.includes('href="data:image/svg+xml,'), 'inline data-URI favicon still present');
  assert.match(html, /href="\/favicon.svg"/);
});
