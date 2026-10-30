const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const CSS = fs.readFileSync(path.join(PUBLIC_DIR, 'css', 'style.css'), 'utf8');
const HTML = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
const APP = fs.readFileSync(path.join(PUBLIC_DIR, 'js', 'app.js'), 'utf8');

test('motion tokens are declared once and reused', () => {
  for (const token of ['--motion-fast', '--motion-base', '--ease-out']) {
    assert.match(CSS, new RegExp(`${token}\\s*:`), `missing motion token ${token}`);
  }
  const uses = [...CSS.matchAll(/var\(--motion-(fast|base)\)/g)].length;
  assert.ok(uses >= 4, `motion tokens barely used (${uses} references)`);
});

test('motion stays bounded: no endless animation loops', () => {
  const loops = [...CSS.matchAll(/animation:[^;]*\binfinite\b/g)].map(m => m[0]);
  // Only the spinner may loop, and only because it marks a real in-flight request.
  const nonSpinner = loops.filter(rule => !/spin/.test(rule));
  assert.deepEqual(nonSpinner, [], `endless loops found: ${nonSpinner.join(' | ')}`);
});

test('the results pane animates in on tab switch', () => {
  assert.match(CSS, /@keyframes\s+pane-enter/, 'pane-enter keyframes missing');
  const block = CSS.match(/\.tab-pane\.active\s*\{([^}]*)\}/);
  assert.ok(block, '.tab-pane.active rule missing');
  assert.match(block[1], /animation:\s*pane-enter/, 'active pane has no entrance animation');
});

test('record rows stagger in rather than all appearing at once', () => {
  assert.match(CSS, /@keyframes\s+row-enter/, 'row-enter keyframes missing');
  assert.match(CSS, /\.record-card\s*\{[^}]*animation:\s*row-enter/s, 'record rows have no entrance animation');
  assert.match(APP, /--row-index|animationDelay|style\.animationDelay/, 'app.js does not stagger row delays');
});

test('progress and toast motion use the shared easing', () => {
  const progress = CSS.match(/\.progress-bar-fill\s*\{([^}]*)\}/);
  assert.ok(progress, 'progress fill rule missing');
  assert.match(progress[1], /transition:/, 'progress fill has no transition');

  const toast = CSS.match(/\.toast\s*\{([^}]*)\}/s);
  assert.ok(toast, 'toast rule missing');
  assert.match(toast[1], /animation:|transition:/, 'toast has no motion');
});

test('every animation is disabled under prefers-reduced-motion', () => {
  const block = CSS.match(/@media \(prefers-reduced-motion: reduce\)\s*\{([\s\S]*?)\n\}/);
  assert.ok(block, 'reduced-motion block missing');
  assert.match(block[1], /animation-duration:\s*0?\.01ms\s*!important/);
  assert.match(block[1], /transition-duration:\s*0?\.01ms\s*!important/);
});

test('the footer groups its links under a brand block and a status line', () => {
  assert.match(HTML, /class="footer-brand"/, 'footer brand block missing');
  assert.match(HTML, /class="footer-bottom"/, 'footer bottom bar missing');
  assert.match(HTML, /class="footer-status"/, 'footer engine status line missing');
  // Three link groups, each with a real heading and at least two links.
  const groups = [...HTML.matchAll(/<section class="footer-group">[\s\S]*?<\/section>/g)];
  assert.ok(groups.length >= 3, `expected 3 footer groups, found ${groups.length}`);
  for (const group of groups) {
    assert.match(group[0], /<h2 class="footer-heading">/, 'footer group lacks a heading');
    const links = group[0].match(/<a /g) || [];
    assert.ok(links.length >= 2, 'footer group has fewer than two links');
  }
});
