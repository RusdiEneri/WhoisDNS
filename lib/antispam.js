/**
 * Form abuse protection for the public lookup endpoint.
 *
 * Strategy (no CAPTCHA, no third-party service, no user tracking):
 *  1. Honeypot fields — hidden inputs must stay empty.
 *  2. Submit timing   — a form submitted faster than a human can type is a bot.
 *
 * Both signals are optional query params sent only by the web UI, so the
 * documented JSON API (curl, scripts, integrations) keeps working unchanged.
 */

const HONEYPOT_FIELDS = ['website', 'company_url', 'fax_number'];
const MIN_HUMAN_SUBMIT_MS = 400;
const TIMING_FIELD = 'form_ts';

const SCRAPER_USER_AGENT = /(masscan|nikto|sqlmap|nmap|acunetix|nessus|dirbuster|gobuster)/i;

function hasFilledHoneypot(query = {}) {
  return HONEYPOT_FIELDS.some(
    field => query[field] !== undefined && String(query[field]).trim() !== ''
  );
}

function submittedTooFast(query = {}) {
  const formTs = Number(query[TIMING_FIELD]);
  if (!Number.isFinite(formTs) || formTs <= 0) return false;
  const elapsed = Date.now() - formTs;
  return elapsed >= 0 && elapsed < MIN_HUMAN_SUBMIT_MS;
}

function looksLikeBot(req, query = {}) {
  if (hasFilledHoneypot(query)) {
    return { blocked: true, reason: 'honeypot' };
  }

  if (submittedTooFast(query)) {
    return { blocked: true, reason: 'submitted_too_fast' };
  }

  if (SCRAPER_USER_AGENT.test(req.get('user-agent') || '')) {
    return { blocked: true, reason: 'known_scanner' };
  }

  return { blocked: false, reason: null };
}

/**
 * Express middleware: rejects spammy submissions while leaving normal API
 * traffic untouched.
 */
function antiSpam() {
  return (req, res, next) => {
    const verdict = looksLikeBot(req, req.query || {});
    if (!verdict.blocked) return next();

    req.antiSpam = verdict;
    res.setHeader('X-Spam-Verdict', verdict.reason);

    return res.status(400).json({
      error: 'Request blocked',
      message: 'Automated submission detected. Please use the website interface.',
      reason: verdict.reason
    });
  };
}

module.exports = {
  antiSpam,
  looksLikeBot,
  hasFilledHoneypot,
  submittedTooFast,
  HONEYPOT_FIELDS,
  MIN_HUMAN_SUBMIT_MS,
  TIMING_FIELD
};
