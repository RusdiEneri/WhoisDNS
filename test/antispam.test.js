const test = require('node:test');
const assert = require('node:assert/strict');
const {
  looksLikeBot,
  hasFilledHoneypot,
  submittedTooFast,
  HONEYPOT_FIELDS,
  TIMING_FIELD
} = require('../lib/antispam');

function fakeReq(userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)') {
  return { get: () => userAgent };
}

test('empty honeypot passes as human', () => {
  assert.equal(hasFilledHoneypot({}), false);
  assert.equal(hasFilledHoneypot({ website: '', company_url: '   ' }), false);
});

test('filled honeypot is detected', () => {
  assert.equal(hasFilledHoneypot({ website: 'http://spam.example' }), true);
  assert.equal(hasFilledHoneypot({ fax_number: '12345' }), true);
  for (const field of HONEYPOT_FIELDS) {
    assert.equal(hasFilledHoneypot({ [field]: 'x' }), true);
  }
});

test('submit timing detects instant submissions only', () => {
  assert.equal(submittedTooFast({}), false);
  assert.equal(submittedTooFast({ [TIMING_FIELD]: String(Date.now()) }), true);
  assert.equal(submittedTooFast({ [TIMING_FIELD]: String(Date.now() - 5000) }), false);
});

test('normal API clients are not blocked', () => {
  const curl = { get: () => 'curl/8.4.0' };
  assert.equal(looksLikeBot(curl, {}).blocked, false);
  assert.equal(looksLikeBot(fakeReq(), {}).blocked, false);
});

test('known scanners are blocked', () => {
  const scanner = { get: () => 'sqlmap/1.7' };
  assert.equal(looksLikeBot(scanner, {}).blocked, true);
  assert.equal(looksLikeBot(scanner, {}).reason, 'known_scanner');
});

test('bot verdict reports the triggering reason', () => {
  assert.equal(looksLikeBot(fakeReq(), { website: 'x' }).reason, 'honeypot');
  assert.equal(
    looksLikeBot(fakeReq(), { [TIMING_FIELD]: String(Date.now()) }).reason,
    'submitted_too_fast'
  );
});
