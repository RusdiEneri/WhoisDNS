const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const HTML = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
const CSS = fs.readFileSync(path.join(PUBLIC_DIR, 'css', 'style.css'), 'utf8');
const APP = fs.readFileSync(path.join(PUBLIC_DIR, 'js', 'app.js'), 'utf8');

/** Collect the id of every element declared in index.html. */
function declaredIds(html) {
  return new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
}

test('every in-page anchor target exists in index.html', () => {
  const ids = declaredIds(HTML);
  const anchors = [...HTML.matchAll(/href="[^"#]*#([A-Za-z][\w-]*)"/g)].map(m => m[1]);
  const missing = [...new Set(anchors)].filter(id => !ids.has(id));
  assert.deepEqual(missing, [], `anchors point at missing ids: ${missing.join(', ')}`);
});

test('heading levels descend without skipping', () => {
  const tags = [...HTML.matchAll(/<h([1-6])[\s>]/g)].map(m => Number(m[1]));
  assert.equal(tags[0], 1, 'first heading must be an h1');
  for (let i = 1; i < tags.length; i++) {
    assert.ok(tags[i] <= tags[i - 1] + 1, `heading level jumped from h${tags[i - 1]} to h${tags[i]}`);
  }
});

test('interactive chips and secondary links meet the 44px tap target', () => {
  const chipBlock = CSS.match(/\.chip-item\s*\{([^}]*)\}/);
  assert.ok(chipBlock, '.chip-item rule missing');
  assert.match(chipBlock[1], /min-height:\s*(44px|[4-9]\dpx|1\d\dpx)/, '.chip-item lacks a 44px tap target');

  for (const selector of ['.breadcrumbs a', '.footer-group a']) {
    const escaped = selector.replace(/\./g, '\\.');
    const block = CSS.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`));
    assert.ok(block, `${selector} rule missing`);
    assert.match(block[1], /min-height:\s*(44px|[4-9]\dpx|1\d\dpx)/, `${selector} lacks a 44px tap target`);
  }
});

test('copy avoids the banned marketing dictionary', () => {
  const banned = [
    'seamless', 'cutting edge', 'cutting-edge', 'next generation', 'next-generation',
    'revolutionary', 'ai powered', 'ai-powered', 'effortless', 'ultimate',
    'get started', 'learn more', 'try now'
  ];
  const haystack = HTML.toLowerCase();
  const hits = banned.filter(word => haystack.includes(word));
  assert.deepEqual(hits, [], `banned copy present: ${hits.join(', ')}`);
});

test('error state names the cause and offers recovery actions', () => {
  assert.match(HTML, /id="error-cause"/, 'missing "what happened" cause block');
  assert.match(HTML, /id="error-causes"/, 'missing potential cause list');
  assert.match(HTML, /id="btn-error-doh"/, 'missing DoH retry action');
  assert.match(HTML, /id="btn-error-history"/, 'missing history action');
});

test('the slash shortcut hint is rendered in the search UI', () => {
  assert.match(HTML, /class="shortcut-hint"/, 'shortcut hint element missing');
  assert.match(HTML, /<kbd>\/<\/kbd>/, 'kbd hint for the slash shortcut missing');
});

test('mobile record table sticks the type column and offers a card view', () => {
  assert.match(CSS, /\.data-table th:first-child[\s\S]{0,200}position:\s*sticky/, 'first column is not sticky');
  assert.match(CSS, /@media \(max-width: 480px\)/, 'no 480px card-view breakpoint');
  assert.match(CSS, /\.record-card\b/, 'record card view styles missing');
});

test('the tab bar shows a scroll affordance on narrow screens', () => {
  assert.match(CSS, /mask-image:\s*linear-gradient/, 'no fade mask on the scrollable tab bar');
});

test('decorative dim text carries a documented reason', () => {
  assert.match(CSS, /--color-text-dim[\s\S]{0,200}decorat/i, 'text-dim reason not documented');
});

test('app.js renders the card view for records on small screens', () => {
  assert.match(APP, /record-card/, 'app.js has no record card rendering path');
});
