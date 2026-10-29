const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const CSS = fs.readFileSync(path.join(PUBLIC_DIR, 'css', 'style.css'), 'utf8');
const HTML = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');

/** Collect every custom property declared in :root blocks. */
function declaredTokens(css) {
  return new Set([...css.matchAll(/(--[a-z0-9-]+)\s*:/g)].map(m => m[1]));
}

function usedTokens(css) {
  return [...new Set([...css.matchAll(/var\((--[a-z0-9-]+)/g)].map(m => m[1]))];
}

test('every CSS custom property used is declared', () => {
  const declared = declaredTokens(CSS);
  const missing = usedTokens(CSS).filter(token => !declared.has(token));
  assert.deepEqual(missing, [], `undeclared tokens: ${missing.join(', ')}`);
});

test('DESIGN.md primitive slate palette is present', () => {
  for (const token of [
    '--primitive-slate-950',
    '--primitive-slate-900',
    '--primitive-slate-850',
    '--primitive-slate-800',
    '--primitive-slate-700',
    '--primitive-slate-600',
    '--primitive-slate-400',
    '--primitive-slate-200',
    '--primitive-white'
  ]) {
    assert.ok(CSS.includes(`${token}:`), `missing primitive token ${token}`);
  }
});

test('DESIGN.md semantic tokens are present', () => {
  for (const token of [
    '--color-bg-base',
    '--color-bg-surface',
    '--color-bg-surface-raised',
    '--color-border-subtle',
    '--color-border-strong',
    '--color-text-main',
    '--color-text-bright',
    '--color-text-muted',
    '--color-status-pass',
    '--color-status-warn',
    '--color-status-fail',
    '--color-focus-ring'
  ]) {
    assert.ok(CSS.includes(`${token}:`), `missing semantic token ${token}`);
  }
});

test('DESIGN.md §7: no artificial glow shadows', () => {
  assert.ok(!/box-shadow:\s*[^;]*rgba\(\s*0\s*,\s*229/.test(CSS), 'neon glow shadow found');
  assert.ok(!/--shadow-glow/.test(CSS), '--shadow-glow token still defined');
  assert.ok(!/text-shadow/.test(CSS), 'text-shadow found');
});

test('DESIGN.md §7: no fake macOS terminal dots', () => {
  assert.ok(!/terminal-dots/.test(CSS), 'terminal-dots rule still present');
  assert.ok(!/terminal-dots/.test(HTML), 'terminal-dots markup still present');
  assert.ok(!/#FF5F56|#FFBD2E|#27C93F/.test(CSS), 'macOS traffic-light colours still present');
});

test('DESIGN.md §7: no decorative gradients or glassmorphism', () => {
  assert.ok(!/linear-gradient/.test(CSS), 'linear-gradient found');
  assert.ok(!/conic-gradient/.test(CSS), 'conic-gradient found');
  assert.ok(!/backdrop-filter/.test(CSS), 'backdrop-filter found');
});

test('DESIGN.md §7: no emoji used as UI icons', () => {
  const emoji = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u;
  assert.ok(!emoji.test(HTML), 'emoji found in markup');
});

test('DESIGN.md §4: reduced-motion block is present', () => {
  assert.match(CSS, /@media \(prefers-reduced-motion: reduce\)/);
});

test('DESIGN.md §3: iOS input font-size guard is present', () => {
  assert.match(CSS, /\.search-input[\s\S]{0,400}font-size:\s*max\(16px/);
  assert.match(CSS, /\.prop-select[\s\S]{0,400}font-size:\s*max\(16px/);
});

test('DESIGN.md §4: tap targets are at least 44px for primary controls', () => {
  for (const selector of ['.btn-primary', '.btn-secondary', '.nav-link', '.tab-btn', '.prop-select']) {
    const escaped = selector.replace('.', '\\.');
    const block = CSS.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`));
    assert.ok(block, `${selector} rule missing`);
    assert.match(block[1], /min-height:\s*(44px|[4-9]\dpx|1\d\dpx)/, `${selector} lacks 44px tap target`);
  }
});

test('record type badges follow the DESIGN.md colour grouping', () => {
  const aBlock = CSS.match(/\.record-badge\.type-A,\s*\n?\.record-badge\.type-AAAA\s*\{([^}]*)\}/);
  assert.ok(aBlock, 'A/AAAA badge grouping missing');
  assert.match(aBlock[1], /color-record-blue/);

  const mxBlock = CSS.match(/\.record-badge\.type-MX\s*\{([^}]*)\}/);
  assert.match(mxBlock[1], /color-record-orange/);

  const txtBlock = CSS.match(/\.record-badge\.type-TXT\s*\{([^}]*)\}/);
  assert.match(txtBlock[1], /color-record-purple/);

  const nsBlock = CSS.match(/\.record-badge\.type-NS,\s*\n?\.record-badge\.type-SOA\s*\{([^}]*)\}/);
  assert.ok(nsBlock, 'NS/SOA badge grouping missing');
  assert.match(nsBlock[1], /color-record-green/);
});

test('HTML loader uses the neutral spinner, not the radar decoration', () => {
  assert.ok(!/radar-scanner/.test(HTML), 'radar-scanner markup still present');
  assert.match(HTML, /class="loading-indicator"/);
});

test('inline style attributes are not used for theming in app.js', () => {
  const app = fs.readFileSync(path.join(PUBLIC_DIR, 'js', 'app.js'), 'utf8');
  assert.ok(!/style="[^"]*color:\s*var\(--/.test(app), 'inline colour styling found in app.js');
});

test('404 page uses design tokens rather than a parallel palette', () => {
  const notFound = fs.readFileSync(path.join(PUBLIC_DIR, '404.html'), 'utf8');
  assert.match(notFound, /var\(--color-text-bright\)/);
  assert.ok(!/#(00E5FF|32D74B|FF453A)/i.test(notFound), 'legacy neon colours in 404 page');
});
