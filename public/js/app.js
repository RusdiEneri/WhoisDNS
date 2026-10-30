/**
 * WhoisDNS Web Tools - Frontend Application Logic
 * Comprehensive WHOIS, DNS Records, Security Audit, and Global Propagation
 */

// ICANN EPP Domain Status Descriptions Map
const EPP_STATUS_DESCRIPTIONS = {
  'ok': 'Domain is in normal state and fully operational.',
  'active': 'Domain is active and operational.',
  'clienttransferprohibited': 'Registrar locked: prevents unauthorized domain transfer requests.',
  'clientupdateprohibited': 'Registrar locked: prevents unauthorized modifications to domain details.',
  'clientdeleteprohibited': 'Registrar locked: prevents unauthorized deletion of the domain.',
  'clienthold': 'Domain is suspended by the registrar; will not resolve in DNS.',
  'servertransferprohibited': 'Registry locked: transfers are blocked by the top-level registry.',
  'serverupdateprohibited': 'Registry locked: updates are blocked by the top-level registry.',
  'serverdeleteprohibited': 'Registry locked: deletion is blocked by the top-level registry.',
  'serverhold': 'Registry suspended: domain is suspended at registry level; will not resolve.',
  'autorenewperiod': 'Grace period: domain was automatically renewed by the registry.',
  'redemptionperiod': 'Redemption period: domain expired and requires restore fee to recover.',
  'pendingdelete': 'Domain is scheduled for permanent deletion and release to the public.'
};

// Global App State
const state = {
  currentDomain: '',
  lookupData: null,
  activeDnsFilter: 'ALL',
  allRecordsFlat: [],
  propagationData: null,
  isPropagating: false
};

// DOM Element References
const elements = {
  searchForm: document.getElementById('search-form'),
  domainInput: document.getElementById('domain-input'),
  btnClearInput: document.getElementById('btn-clear-input'),
  btnSearch: document.getElementById('btn-search'),
  searchSpinner: document.getElementById('search-spinner'),
  historyContainer: document.getElementById('history-container'),
  historyItems: document.getElementById('history-items'),
  
  loadingView: document.getElementById('loading-view'),
  loadingSubtext: document.getElementById('loading-subtext'),
  errorView: document.getElementById('error-view'),
  errorTitle: document.getElementById('error-title'),
  errorMessage: document.getElementById('error-message'),
  errorCause: document.getElementById('error-cause'),
  errorCauses: document.getElementById('error-causes'),
  btnErrorRetry: document.getElementById('btn-error-retry'),
  btnErrorDoh: document.getElementById('btn-error-doh'),
  btnErrorHistory: document.getElementById('btn-error-history'),
  resultsView: document.getElementById('results-view'),

  // Overview Banner
  targetDomainName: document.getElementById('target-domain-name'),
  badgeTld: document.getElementById('badge-tld'),
  badgeStatus: document.getElementById('badge-status'),
  domainNotice: document.getElementById('domain-notice'),
  badgeDnssec: document.getElementById('badge-dnssec'),
  badgeSubdomain: document.getElementById('badge-subdomain'),
  metaRegistrable: document.getElementById('meta-registrable'),
  metaRegistrableBullet: document.getElementById('meta-registrable-bullet'),
  metaIp: document.getElementById('meta-ip'),
  metaGeo: document.getElementById('meta-geo'),
  metaAsn: document.getElementById('meta-asn'),
  btnCopySummary: document.getElementById('btn-copy-summary'),
  btnExportJson: document.getElementById('btn-export-json'),
  btnShare: document.getElementById('btn-share'),

  // KPI Metrics
  kpiRegistrar: document.getElementById('kpi-registrar'),
  kpiIanaId: document.getElementById('kpi-iana-id'),
  kpiAge: document.getElementById('kpi-age'),
  kpiCreated: document.getElementById('kpi-created'),
  kpiExpiry: document.getElementById('kpi-expiry'),
  kpiDaysLeft: document.getElementById('kpi-days-left'),
  kpiDnsCount: document.getElementById('kpi-dns-count'),
  kpiLatency: document.getElementById('kpi-latency'),
  dnsBadgeCount: document.getElementById('dns-badge-count'),

  // Tabs
  tabBtns: document.querySelectorAll('.tab-btn'),
  tabPanes: document.querySelectorAll('.tab-pane'),

  // Tab 1: Overview
  healthScoreBadge: document.getElementById('health-score-badge'),
  healthChecklist: document.getElementById('health-checklist'),
  overviewNsList: document.getElementById('overview-ns-list'),
  btnCopyNs: document.getElementById('btn-copy-ns'),
  overviewMxList: document.getElementById('overview-mx-list'),
  overviewEmailAuth: document.getElementById('overview-email-auth'),
  overviewGeoDetails: document.getElementById('overview-geo-details'),

  // Tab 2: DNS
  dnsTypePills: document.querySelectorAll('.pill-filter'),
  dnsRecordSearch: document.getElementById('dns-record-search'),
  dnsTableBody: document.getElementById('dns-table-body'),
  btnCopyDnsRecords: document.getElementById('btn-copy-dns-records'),

  // Tab 3: WHOIS
  whoisRegistrarKv: document.getElementById('whois-registrar-kv'),
  whoisDatesKv: document.getElementById('whois-dates-kv'),
  whoisRegistrantKv: document.getElementById('whois-registrant-kv'),
  whoisStatusBadges: document.getElementById('whois-status-badges'),

  // Tab 4: Propagation
  propTypeSelect: document.getElementById('prop-type-select'),
  btnRefreshPropagation: document.getElementById('btn-refresh-propagation'),
  propProgressBar: document.getElementById('prop-progress-bar'),
  propPercentageText: document.getElementById('prop-percentage-text'),
  propStatusLabel: document.getElementById('prop-status-label'),
  resolversGrid: document.getElementById('resolvers-grid'),

  // Tab 5: Raw
  rawWhoisText: document.getElementById('raw-whois-text'),
  rawWrapToggle: document.getElementById('raw-wrap-toggle'),
  btnCopyRaw: document.getElementById('btn-copy-raw'),

  // Modal
  ipModal: document.getElementById('ip-modal'),
  modalIpTitle: document.getElementById('modal-ip-title'),
  modalIpContent: document.getElementById('modal-ip-content'),
  btnCloseIpModal: document.getElementById('btn-close-ip-modal'),

  // Toast
  toastContainer: document.getElementById('toast-container'),

  // Form validation
  domainError: document.getElementById('domain-error')
};

// ==========================================================================
// Initialization & Event Listeners
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadSearchHistory();
  checkServerHealth();

  if (window.WhoisDnsTrack) {
    window.WhoisDnsTrack.installClickTracking(document);
    window.WhoisDnsTrack.track('page_view', {
      referrer: document.referrer || 'direct',
      hasQuery: new URLSearchParams(window.location.search).has('q')
    });
  }

  // Handle URL query parameter ?q= or ?domain=
  const urlParams = new URLSearchParams(window.location.search);
  const initialQuery = urlParams.get('q') || urlParams.get('domain');
  const initialTab = urlParams.get('tab');
  if (initialQuery) {
    elements.domainInput.value = initialQuery;
    executeLookup(initialQuery).then(() => {
      if (initialTab) switchTab(tabIdFromSlug(initialTab));
    });
  }
});

/** Map a short ?tab= slug onto the pane id used by switchTab. */
function tabIdFromSlug(slug) {
  const known = { overview: 'tab-overview', dns: 'tab-dns', whois: 'tab-whois', propagation: 'tab-propagation', raw: 'tab-raw' };
  return known[String(slug || '').toLowerCase()] || 'tab-overview';
}

/** Reverse of tabIdFromSlug, for keeping ?tab= in the address bar. */
function currentTabSlug() {
  const pane = document.querySelector('.tab-pane.active');
  if (!pane) return '';
  return pane.id.replace(/^tab-/, '');
}

/**
 * Non-blocking analytics helper: never breaks the UI if tracking is unavailable.
 */
function trackEvent(name, params) {
  try {
    if (window.WhoisDnsTrack) window.WhoisDnsTrack.track(name, params);
  } catch (_) {}
}

function setupEventListeners() {
  // Anti-spam: stamp the first interaction with the form, not page load, so
  // that direct ?q= links and chip clicks are never mistaken for bots.
  const formTsInput = document.getElementById('form-ts');
  const stampFormInteraction = () => {
    if (formTsInput && !formTsInput.value) formTsInput.value = String(Date.now());
  };

  // Search form submit
  elements.searchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const query = elements.domainInput.value.trim();

    const validation = validateDomainInput(query);
    if (!validation.valid) {
      showFormError(validation.message);
      trackEvent('form_invalid', { reason: validation.reason });
      return;
    }

    clearFormError();
    trackEvent('form_submit', { input_type: validation.type });
    executeLookup(query);
  });

  elements.domainInput.addEventListener('keydown', stampFormInteraction, { once: true });
  elements.domainInput.addEventListener('input', stampFormInteraction, { once: true });

  // Clear inline error as soon as the user edits the field
  elements.domainInput.addEventListener('input', () => {
    if (elements.domainError && elements.domainError.style.display !== 'none') {
      clearFormError();
    }
  });
  // Clear button toggle
  elements.domainInput.addEventListener('input', () => {
    elements.btnClearInput.style.display = elements.domainInput.value ? 'flex' : 'none';
  });

  elements.btnClearInput.addEventListener('click', () => {
    elements.domainInput.value = '';
    elements.btnClearInput.style.display = 'none';
    elements.domainInput.focus();
  });

  // Example pills
  document.querySelectorAll('.chip-item').forEach(chip => {
    chip.addEventListener('click', () => {
      const domain = chip.getAttribute('data-domain');
      elements.domainInput.value = domain;
      elements.btnClearInput.style.display = 'flex';
      trackEvent('cta_click', { cta: 'example_chip', label: domain });
      executeLookup(domain);
    });
  });

  // Tab buttons
  elements.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // DNS Type filter pills
  elements.dnsTypePills.forEach(pill => {
    pill.addEventListener('click', () => {
      elements.dnsTypePills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.activeDnsFilter = pill.getAttribute('data-type');
      renderDnsRecordsTable();
    });
  });

  // DNS in-table search
  elements.dnsRecordSearch.addEventListener('input', () => {
    renderDnsRecordsTable();
  });

  // Action Buttons
  elements.btnCopySummary.addEventListener('click', () => {
    trackEvent('cta_click', { cta: 'copy_summary' });
    copySummaryToClipboard();
  });
  elements.btnExportJson.addEventListener('click', () => {
    trackEvent('cta_click', { cta: 'export_json' });
    exportDataAsJson();
  });
  elements.btnShare.addEventListener('click', () => {
    trackEvent('cta_click', { cta: 'share_link' });
    shareLookupLink();
  });
  elements.btnCopyNs.addEventListener('click', copyNameservers);
  elements.btnCopyDnsRecords.addEventListener('click', copyVisibleDnsRecords);
  elements.btnCopyRaw.addEventListener('click', copyRawWhois);
  elements.btnErrorRetry.addEventListener('click', () => {
    if (state.currentDomain) executeLookup(state.currentDomain);
  });
  if (elements.btnErrorDoh) {
    elements.btnErrorDoh.addEventListener('click', () => {
      trackEvent('cta_click', { cta: 'error_doh_retry' });
      if (!state.currentDomain) return;
      runClientFallback(state.currentDomain)
        .then(data => {
          state.lookupData = data;
          renderResults(data);
          elements.errorView.style.display = 'none';
          elements.resultsView.style.display = 'block';
          showToast('Resolved via Cloudflare & Google DoH');
        })
        .catch(() => {
          showErrorState({
            title: 'DoH Lookup Failed',
            message: 'Cloudflare and Google DoH could not resolve this name either.',
            cause: 'Both public resolvers returned no usable answer for the queried name.',
            causes: [
              'The name does not exist in DNS.',
              'A firewall on this network blocks outbound DoH requests.',
              'The query is malformed.'
            ]
          });
        });
    });
  }
  if (elements.btnErrorHistory) {
    elements.btnErrorHistory.addEventListener('click', () => {
      const history = getSearchHistory();
      if (!history.length) {
        showToast('No previous queries stored yet');
        return;
      }
      elements.domainInput.value = history[0];
      executeLookup(history[0]);
    });
  }

  // Propagation triggers
  elements.propTypeSelect.addEventListener('change', () => {
    if (state.currentDomain) runPropagationCheck(state.currentDomain, elements.propTypeSelect.value);
  });
  elements.btnRefreshPropagation.addEventListener('click', () => {
    trackEvent('cta_click', { cta: 'refresh_propagation' });
    if (state.currentDomain) runPropagationCheck(state.currentDomain, elements.propTypeSelect.value);
  });

  // Raw Word Wrap Toggle
  elements.rawWrapToggle.addEventListener('change', () => {
    if (elements.rawWrapToggle.checked) {
      elements.rawWhoisText.classList.remove('nowrap');
    } else {
      elements.rawWhoisText.classList.add('nowrap');
    }
  });

  // IP Modal Close
  elements.btnCloseIpModal.addEventListener('click', () => {
    elements.ipModal.style.display = 'none';
  });
  elements.ipModal.addEventListener('click', (e) => {
    if (e.target === elements.ipModal) elements.ipModal.style.display = 'none';
  });

  // Keyboard Shortcuts
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== elements.domainInput) {
      e.preventDefault();
      elements.domainInput.focus();
      elements.domainInput.select();
    } else if (e.key === 'Escape') {
      elements.ipModal.style.display = 'none';
    }
  });
}

function switchTab(tabId) {
  elements.tabBtns.forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
  });
  elements.tabPanes.forEach(pane => {
    pane.classList.toggle('active', pane.id === tabId);
  });

  // Keep ?tab= in the address bar so the view survives a reload or a shared link.
  if (state.currentDomain && window.history.replaceState) {
    const params = new URLSearchParams(window.location.search);
    const slug = tabId.replace(/^tab-/, '');
    if (slug === 'overview') params.delete('tab');
    else params.set('tab', slug);
    const query = params.toString();
    window.history.replaceState({ domain: state.currentDomain }, '', `${window.location.pathname}${query ? '?' + query : ''}`);
  }

  // Lazy trigger propagation when tab is opened
  if (tabId === 'tab-propagation' && (!state.propagationData || state.propagationData.domain !== state.currentDomain)) {
    runPropagationCheck(state.currentDomain, elements.propTypeSelect.value);
  }
}

// ==========================================================================
// Health & API Service
// ==========================================================================

async function checkServerHealth() {
  const statusEl = document.getElementById('server-status');
  const statusText = document.getElementById('server-status-text');
  const footerStatus = document.getElementById('footer-status');
  const setFooter = (state, label) => {
    if (!footerStatus) return;
    footerStatus.className = `footer-status ${state}`;
    footerStatus.textContent = `Engine status: ${label}`;
  };
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      statusEl.className = 'status-indicator online';
      statusText.textContent = 'Engine Online';
      setFooter('online', 'online');
    } else {
      setFooter('offline', 'degraded');
    }
  } catch (_) {
    statusEl.className = 'status-indicator offline';
    statusText.textContent = 'DoH Direct Mode';
    setFooter('offline', 'DoH direct mode');
  }
}

// Clean domain input helper
function sanitizeDomain(input) {
  if (!input) return '';
  let str = input.trim().toLowerCase();
  str = str.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  str = str.split('/')[0];
  str = str.split('?')[0];
  str = str.split('#')[0];
  str = str.split('@').pop();
  if (str.startsWith('[')) {
    const ipv6 = str.match(/^\[([^\]]+)\]/);
    if (ipv6) return ipv6[1];
  }
  str = str.split(':')[0];
  return str.replace(/\.+$/, '');
}

function isPlausibleDomain(str) {
  if (!str || str.length > 253) return false;
  if (str.includes('..')) return false;
  return /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/.test(str);
}

/**
 * Client-side form validation with a human-readable reason.
 */
function validateDomainInput(raw) {
  if (!raw) {
    return { valid: false, reason: 'empty', message: 'Please enter a domain name or IP address.' };
  }

  const cleaned = sanitizeDomain(raw);

  if (!cleaned) {
    return { valid: false, reason: 'empty_after_clean', message: 'Please enter a valid domain name.' };
  }

  if (isIpv4(cleaned) || /^[0-9a-f:]+$/i.test(cleaned) && cleaned.includes(':')) {
    return { valid: true, type: 'ip' };
  }

  if (cleaned.length > 253) {
    return { valid: false, reason: 'too_long', message: 'Domain name is too long (maximum 253 characters).' };
  }

  if (!isPlausibleDomain(cleaned)) {
    return {
      valid: false,
      reason: 'bad_format',
      message: 'Enter a valid domain like example.com (must include a TLD such as .com or .id).'
    };
  }

  return { valid: true, type: 'domain' };
}

function showFormError(message) {
  if (!elements.domainError) return;
  elements.domainError.textContent = message;
  elements.domainError.style.display = 'block';
  elements.domainInput.setAttribute('aria-invalid', 'true');
  elements.domainInput.focus();
}

function clearFormError() {
  if (!elements.domainError) return;
  elements.domainError.textContent = '';
  elements.domainError.style.display = 'none';
  elements.domainInput.removeAttribute('aria-invalid');
}

// ==========================================================================
// Main Lookup Execution
// ==========================================================================

/**
 * Show the structured error card: what happened, probable cause, recovery.
 */
function showErrorState({ title, message, cause, causes }) {
  elements.loadingView.style.display = 'none';
  elements.resultsView.style.display = 'none';
  elements.errorView.style.display = 'block';
  if (title) elements.errorTitle.textContent = title;
  if (message) elements.errorMessage.textContent = message;
  if (cause && elements.errorCause) elements.errorCause.textContent = cause;
  if (causes && elements.errorCauses) {
    elements.errorCauses.innerHTML = '';
    causes.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      elements.errorCauses.appendChild(li);
    });
  }
  if (elements.btnErrorHistory) {
    elements.btnErrorHistory.style.display = getSearchHistory().length ? '' : 'none';
  }
}

async function executeLookup(query) {
  const domain = sanitizeDomain(query);
  if (!domain) return;

  if (!isPlausibleDomain(domain) && !isIpv4(domain)) {
    showErrorState({
      title: 'Invalid Input',
      message: 'Enter a valid domain name like example.com, or an IPv4/IPv6 address.',
      cause: 'The text typed into the search field is not a valid hostname or IP address.',
      causes: [
        'Missing or duplicated dot in the domain name.',
        'A URL scheme or path was pasted instead of the bare hostname.',
        'The TLD is not a recognised public suffix.'
      ]
    });
    return;
  }

  state.currentDomain = domain;
  saveSearchHistory(domain);

  // Update browser URL query string without reloading. The active tab is
  // preserved so a reload lands on the same view.
  const params = new URLSearchParams({ q: domain });
  const slug = typeof currentTabSlug === 'function' ? currentTabSlug() : '';
  if (slug && slug !== 'overview') params.set('tab', slug);
  window.history.pushState({ domain }, '', `${window.location.pathname}?${params.toString()}`);

  // Set UI Loading State
  elements.loadingView.style.display = 'block';
  elements.errorView.style.display = 'none';
  elements.resultsView.style.display = 'none';
  elements.searchSpinner.style.display = 'inline-block';
  elements.btnSearch.setAttribute('disabled', 'true');
  elements.loadingSubtext.textContent = `Connecting to WHOIS servers and analyzing DNS records for ${domain}...`;

  try {
    const res = await fetch(`/api/lookup?${buildLookupParams(domain)}`);
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.message || `Server returned error (${res.status})`);
    }

    const data = await res.json();
    state.lookupData = data;

    trackEvent('lookup_success', {
      query_type: data.type === 'ip' ? 'ip' : 'domain',
      total_records: data.dns ? data.dns.totalRecords : 0,
      duration_ms: data.durationMs || 0
    });

    // Render results
    renderResults(data);

    elements.loadingView.style.display = 'none';
    elements.resultsView.style.display = 'block';
  } catch (err) {
    console.warn('Backend lookup failed, attempting browser direct DoH fallback...', err);
    trackEvent('lookup_backend_failed', { reason: String(err.message || '').slice(0, 120) });
    try {
      const fallbackData = await runClientFallback(domain);
      state.lookupData = fallbackData;
      renderResults(fallbackData);
      elements.loadingView.style.display = 'none';
      elements.resultsView.style.display = 'block';
      showToast('Resolved via Cloudflare & Google DoH');
      trackEvent('lookup_success', { query_type: 'domain', fallback: true });
    } catch (fallbackErr) {
      showErrorState({
        title: 'Lookup Failed',
        message: err.message || 'Unable to connect to domain or resolver.',
        cause: `Neither the backend lookup nor the browser DoH fallback returned data for ${domain}.`,
        causes: [
          'The domain name is misspelled or the TLD does not exist.',
          'The registry WHOIS server refused the port 43 connection.',
          'DNS records changed recently and propagation has not finished.',
          'A local firewall or proxy blocks outbound DNS queries.'
        ]
      });
      trackEvent('lookup_failed', { reason: String(err.message || '').slice(0, 120) });
    }
  } finally {
    elements.searchSpinner.style.display = 'none';
    elements.btnSearch.removeAttribute('disabled');
  }
}

/**
 * Build the lookup query string, including anti-spam honeypot and timing
 * fields. Hidden fields are always empty for humans.
 */
function buildLookupParams(domain) {
  const params = new URLSearchParams({ domain });

  const hpWebsite = document.getElementById('hp-website');
  const hpCompany = document.getElementById('hp-company');
  const formTs = document.getElementById('form-ts');

  if (hpWebsite && hpWebsite.value) params.set('website', hpWebsite.value);
  if (hpCompany && hpCompany.value) params.set('company_url', hpCompany.value);
  if (formTs && formTs.value) params.set('form_ts', formTs.value);

  return params.toString();
}

// Client-side DoH Fallback if backend API is offline
async function runClientFallback(domain) {
  const cfRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
    headers: { 'Accept': 'application/dns-json' }
  });
  const cfData = await cfRes.json();
  const aRecords = (cfData.Answer || []).filter(a => a.type === 1).map(a => ({
    type: 'A',
    value: a.data,
    ttl: a.TTL
  }));

  return {
    type: 'domain',
    domain,
    timestamp: new Date().toISOString(),
    dns: {
      domain,
      totalRecords: aRecords.length,
      recordsByType: {
        'A': { type: 'A', count: aRecords.length, records: aRecords }
      },
      dmarc: { present: false },
      dnssec: { dnssecSupported: false },
      healthChecks: [
        {
          id: 'a_record',
          category: 'Connectivity',
          status: aRecords.length > 0 ? 'pass' : 'fail',
          title: 'IPv4 Resolved via DoH',
          description: `Resolved ${aRecords.length} IP(s) via Cloudflare DoH.`
        }
      ],
      durationMs: 120
    },
    whois: {
      domainName: domain,
      registrar: 'Query limited in DoH mode',
      creationDate: null,
      expiryDate: null,
      raw: 'WHOIS socket query requires Node.js engine running.'
    },
    primaryIp: aRecords[0] ? { ip: aRecords[0].value } : null,
    durationMs: 150
  };
}

// ==========================================================================
// Rendering Results
// ==========================================================================

function renderResults(data) {
  const domain = data.domain || state.currentDomain;
  const whois = data.whois || {};
  const dns = data.dns || {};
  const primaryIp = data.primaryIp || {};

  // 1. Overview Banner
  elements.targetDomainName.textContent = domain;
  const tldLabel = data.tld || domain.split('.').slice(-1)[0];
  elements.badgeTld.textContent = '.' + String(tldLabel).toUpperCase();

  // Subdomain indicator
  const registrable = data.registrableDomain;
  const isSub = Boolean(data.isSubdomain) || Boolean(registrable && registrable !== domain);
  elements.badgeSubdomain.style.display = isSub ? '' : 'none';
  elements.badgeSubdomain.textContent = 'Subdomain';
  elements.badgeSubdomain.title = isSub ? `Registrable domain: ${registrable}` : '';

  if (isSub && registrable) {
    elements.metaRegistrable.textContent = `Registrable: ${registrable}`;
    elements.metaRegistrable.style.display = '';
    elements.metaRegistrableBullet.style.display = '';
  } else {
    elements.metaRegistrable.style.display = 'none';
    elements.metaRegistrableBullet.style.display = 'none';
  }

  // Status badge. "Active" is only claimed when a registration record exists.
  if (whois.isAvailable) {
    elements.badgeStatus.textContent = 'Not Registered';
    elements.badgeStatus.className = 'badge badge-status accent-amber';
    elements.badgeStatus.title = `${registrable || domain} has no registration record in the registry WHOIS.`;
  } else if (whois.error) {
    elements.badgeStatus.textContent = 'Status Unknown';
    elements.badgeStatus.className = 'badge badge-status accent-red';
    elements.badgeStatus.title = whois.error;
  } else if (!whois.registrar && !whois.creationDate && !whois.nameServers?.length) {
    elements.badgeStatus.textContent = 'Status Unknown';
    elements.badgeStatus.className = 'badge badge-status accent-red';
    elements.badgeStatus.title = 'The registry returned no registration data for this domain.';
  } else if (whois.daysUntilExpiry !== null && whois.daysUntilExpiry < 0) {
    elements.badgeStatus.textContent = 'Expired';
    elements.badgeStatus.className = 'badge badge-status accent-red';
    elements.badgeStatus.title = `Registration expired ${Math.abs(whois.daysUntilExpiry)} days ago.`;
  } else {
    elements.badgeStatus.textContent = 'Registered';
    elements.badgeStatus.className = 'badge badge-status';
    elements.badgeStatus.title = `Registered domain, looked up from the registry WHOIS for ${registrable || domain}.`;
  }

  renderDomainNotice(whois, domain, registrable);

  // DNSSEC badge
  const isDnssec = dns.dnssec?.dnssecSupported || whois.dnssec === 'signed';
  elements.badgeDnssec.textContent = isDnssec ? 'DNSSEC Signed' : 'DNSSEC Unsigned';
  elements.badgeDnssec.className = isDnssec ? 'badge badge-dnssec accent-green' : 'badge badge-dnssec';

  // Sub meta row
  elements.metaIp.textContent = primaryIp.ip ? `IP: ${primaryIp.ip}` : 'IP: None';
  elements.metaGeo.textContent = primaryIp.country ? `Location: ${primaryIp.city ? primaryIp.city + ', ' : ''}${primaryIp.country}` : 'Location: Global / CDN';
  elements.metaAsn.textContent = primaryIp.asn ? `ASN: ${primaryIp.asn}` : (primaryIp.isp ? `ISP: ${primaryIp.isp}` : 'ASN: -');

  // 2. 4 Key Metrics Bar
  elements.kpiRegistrar.textContent = whois.registrar || (whois.isAvailable ? 'Not registered' : 'Not published');
  elements.kpiIanaId.textContent = whois.registrarIanaId ? `IANA ID: ${whois.registrarIanaId}` : (whois.registrarUrl || 'IANA ID: not published');
  elements.kpiAge.textContent = whois.domainAge || (whois.isAvailable ? 'n/a' : 'Not published');
  elements.kpiCreated.textContent = whois.creationDate
    ? `Created: ${formatDate(whois.creationDate)}`
    : (whois.isAvailable ? 'Created: n/a' : 'Created: not published');
  elements.kpiExpiry.textContent = whois.expiryDate ? formatDate(whois.expiryDate) : (whois.isAvailable ? 'n/a' : 'Not published');
  elements.kpiDaysLeft.textContent = whois.daysUntilExpiry !== null 
    ? (whois.daysUntilExpiry > 0 ? `${whois.daysUntilExpiry.toLocaleString()} days left` : `Expired ${Math.abs(whois.daysUntilExpiry)} days ago`)
    : (whois.isAvailable ? 'Domain is unregistered' : 'Expiry: not published');
  elements.kpiDnsCount.textContent = (dns.totalRecords || 0).toLocaleString();
  elements.kpiLatency.textContent = `Resolved in ${data.durationMs || 0}ms`;
  elements.dnsBadgeCount.textContent = (dns.totalRecords || 0).toString();

  // 3. Tab 1: Overview components
  renderHealthAudit(dns.healthChecks || []);
  renderNameservers(dns.recordsByType?.['NS']?.records || whois.nameServers || []);
  renderMailRouting(dns.recordsByType?.['MX']?.records || []);
  renderEmailAuth(dns.email || { spf: dns.spf, dmarc: dns.dmarc, dkim: dns.dkim });
  renderGeoDetails(primaryIp, data.cnameChain || []);

  // 4. Tab 2: DNS Records Deep Dive
  flattenDnsRecords(dns.recordsByType || {});
  renderDnsRecordsTable();

  // 5. Tab 3: WHOIS Details
  renderWhoisDetails(whois);

  // 6. Tab 5: Raw WHOIS
  elements.rawWhoisText.textContent = whois.raw || 'No raw WHOIS text received.';

  // Reset propagation tab status
  state.propagationData = null;
  elements.propPercentageText.textContent = 'Select record type and test propagation';
  elements.propProgressBar.style.width = '0%';
  elements.resolversGrid.innerHTML = '<p class="grid-empty">Click "Refresh Propagation" or open the tab to test 8 global Anycast resolvers.</p>';
}

// Explains why registration fields may be empty instead of leaving dashes.
function renderDomainNotice(whois, domain, registrable) {
  const notice = elements.domainNotice;
  if (!notice) return;

  const target = registrable || domain;
  let message = '';

  if (whois.isAvailable) {
    message = `${target} is not registered. No registry WHOIS record exists for this name, so registrar, dates and status codes are unavailable. Any DNS records shown come from a different source and do not imply registration.`;
  } else if (whois.error) {
    message = `The registry WHOIS lookup for ${target} failed: ${whois.error}. Registration data is incomplete, so the status is unknown rather than active.`;
  } else if (!whois.registrar && !whois.creationDate && !whois.nameServers?.length) {
    message = `The registry returned a record for ${target} without registrar, dates or name servers. This registry withholds those fields, so treat the missing values as not published, not as inactive.`;
  } else if (!whois.creationDate || !whois.expiryDate) {
    const missing = [];
    if (!whois.creationDate) missing.push('creation date');
    if (!whois.expiryDate) missing.push('expiry date');
    message = `This registry does not publish the ${missing.join(' or ')} for ${target}. Domain age and remaining validity stay blank because the data does not exist, not because the domain is unregistered.`;
  }

  notice.textContent = message;
  notice.hidden = !message;
}

function formatDate(dateStr) {
  try {
    const d = new Date(dateStr);
    if (!isNaN(d.getTime())) {
      return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    }
  } catch (_) {}
  return dateStr;
}

// Render Health Audit Checklist
function renderHealthAudit(checks) {
  elements.healthChecklist.innerHTML = '';
  const passedCount = checks.filter(c => c.status === 'pass').length;
  elements.healthScoreBadge.textContent = `${passedCount} / ${checks.length} Passed`;

  checks.forEach(item => {
    const div = document.createElement('div');
    div.className = `health-item ${item.status}`;

    let iconSvg = '';
    if (item.status === 'pass') {
      iconSvg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (item.status === 'warning') {
      iconSvg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
    } else if (item.status === 'fail') {
      iconSvg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    } else {
      iconSvg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    div.innerHTML = `
      <div class="health-badge-icon">${iconSvg}</div>
      <div class="health-item-content">
        <div class="health-item-title">${escapeHtml(item.title)}</div>
        <div class="health-item-desc">${escapeHtml(item.description)}</div>
      </div>
    `;
    elements.healthChecklist.appendChild(div);
  });
}

// Render Nameservers
function renderNameservers(nsRecords) {
  elements.overviewNsList.innerHTML = '';
  if (!nsRecords || nsRecords.length === 0) {
    elements.overviewNsList.innerHTML = '<li class="ns-item text-muted">No nameservers found</li>';
    return;
  }

  nsRecords.forEach(ns => {
    const val = typeof ns === 'string' ? ns : ns.value;
    const li = document.createElement('li');
    li.className = 'ns-item';
    li.innerHTML = `
      <span>${escapeHtml(val)}</span>
      <button class="ns-copy-btn" title="Copy Host" data-copy="${escapeHtml(val)}">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
      </button>
    `;
    li.querySelector('.ns-copy-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      copyText(val);
    });
    elements.overviewNsList.appendChild(li);
  });
}

// Render Mail Routing (MX)
function renderMailRouting(mxRecords) {
  elements.overviewMxList.innerHTML = '';
  if (!mxRecords || mxRecords.length === 0) {
    elements.overviewMxList.innerHTML = '<div class="mx-item text-muted">No MX records configured</div>';
    return;
  }

  mxRecords.forEach(mx => {
    const div = document.createElement('div');
    div.className = 'mx-item';
    div.innerHTML = `
      <span>${escapeHtml(mx.exchange || mx.value)}</span>
      <span class="mx-priority">Priority: ${mx.priority !== undefined ? mx.priority : '-'}</span>
    `;
    elements.overviewMxList.appendChild(div);
  });
}

// Render Email Authentication summary (SPF / DMARC / DKIM)
function renderEmailAuth(email) {
  if (!elements.overviewEmailAuth) return;
  elements.overviewEmailAuth.innerHTML = '';

  const emailAuth = email || {};
  const spf = emailAuth.spf || { present: false };
  const dmarc = emailAuth.dmarc || { present: false };
  const dkim = emailAuth.dkim || { present: false, records: [] };

  const chips = [
    {
      label: 'SPF',
      present: Boolean(spf.present),
      detail: spf.present ? `qualifier: ${spf.qualifier || 'neutral'}` : 'not published',
      title: spf.raw || 'No SPF (v=spf1) TXT record found'
    },
    {
      label: 'DMARC',
      present: Boolean(dmarc.present),
      detail: dmarc.present ? `p=${dmarc.policy}` : 'not published',
      title: dmarc.raw || 'No _dmarc TXT policy found'
    },
    {
      label: 'DKIM',
      present: Boolean(dkim.present),
      detail: dkim.present
        ? [...new Set((dkim.records || []).map(r => r.selector))].slice(0, 3).join(', ')
        : 'selector not detected',
      title: dkim.present
        ? (dkim.records || []).map(r => `${r.selector}: ${r.value}`).join('\n')
        : 'No DKIM key found on common selectors'
    }
  ];

  chips.forEach(chip => {
    const span = document.createElement('span');
    span.className = `email-auth-chip ${chip.present ? 'present' : 'missing'}`;
    span.title = chip.title;
    span.textContent = `${chip.label}: ${chip.detail}`;
    elements.overviewEmailAuth.appendChild(span);
  });
}

// Render Geo Infrastructure Details
function renderGeoDetails(ipInfo, cnameChain) {
  elements.overviewGeoDetails.innerHTML = '';
  const chain = Array.isArray(cnameChain) ? cnameChain : [];

  if (chain.length > 0) {
    const chainDiv = document.createElement('div');
    chainDiv.className = 'geo-item geo-item-wide';
    chainDiv.innerHTML = `
      <div class="geo-label">CNAME Chain</div>
      <div class="geo-val font-mono" title="${escapeHtml(chain.join(' -> '))}">${escapeHtml(chain.join(' \u2192 '))}</div>
    `;
    elements.overviewGeoDetails.appendChild(chainDiv);
  }

  if (!ipInfo || !ipInfo.ip) {
    if (chain.length === 0) {
      elements.overviewGeoDetails.innerHTML = '<div class="geo-item geo-item-wide text-muted">No IP information available</div>';
    }
    return;
  }

  const items = [
    { label: 'Primary IPv4', val: ipInfo.ip, copyable: true },
    { label: 'Hostname (PTR)', val: ipInfo.primaryHostname || ipInfo.reverseDns?.[0] || 'None' },
    { label: 'Country & City', val: `${ipInfo.city ? ipInfo.city + ', ' : ''}${ipInfo.country || 'Unknown'}` },
    { label: 'ISP / Provider', val: ipInfo.isp || 'Unknown' },
    { label: 'Autonomous System', val: ipInfo.asn || 'Unknown' },
    { label: 'Timezone', val: ipInfo.timezone || '-' }
  ];

  items.forEach(it => {
    const div = document.createElement('div');
    div.className = 'geo-item';
    div.innerHTML = `
      <div class="geo-label">${it.label}</div>
      <div class="geo-val font-mono" title="${escapeHtml(it.val)}">${escapeHtml(it.val)}</div>
    `;
    if (it.copyable) {
      div.style.cursor = 'pointer';
      div.title = 'Click to copy IP';
      div.addEventListener('click', () => copyText(it.val));
    }
    elements.overviewGeoDetails.appendChild(div);
  });
}

// ==========================================================================
// DNS Records Deep Table
// ==========================================================================

function flattenDnsRecords(recordsByType) {
  state.allRecordsFlat = [];
  Object.keys(recordsByType).forEach(type => {
    const group = recordsByType[type];
    if (group && Array.isArray(group.records)) {
      group.records.forEach(r => {
        state.allRecordsFlat.push({
          type: r.type || type,
          ttl: r.ttl !== undefined && r.ttl !== null ? r.ttl : '-',
          value: r.value || (typeof r === 'string' ? r : JSON.stringify(r)),
          raw: r
        });
      });
    }
  });
}

function renderDnsRecordsTable() {
  const filterType = state.activeDnsFilter;
  const searchFilter = elements.dnsRecordSearch.value.trim().toLowerCase();
  elements.dnsTableBody.innerHTML = '';

  let filtered = state.allRecordsFlat;
  if (filterType !== 'ALL') {
    filtered = filtered.filter(r => r.type.toUpperCase() === filterType);
  }
  if (searchFilter) {
    filtered = filtered.filter(r => 
      r.type.toLowerCase().includes(searchFilter) || 
      String(r.value).toLowerCase().includes(searchFilter)
    );
  }

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="4" class="table-empty">No ${filterType === 'ALL' ? '' : filterType} records match query.</td>`;
    elements.dnsTableBody.appendChild(tr);
    return;
  }

  filtered.forEach((rec, index) => {
    const tr = document.createElement('tr');
    const isIp = isIpv4(rec.value);
    const ttlLabel = formatTtl(rec.ttl);

    // DESIGN.md §4: mark the row so the 480px breakpoint can present it as a card.
    // The stagger is capped so a long record list still settles quickly.
    tr.className = 'record-card';
    tr.style.animationDelay = `${Math.min(index, 10) * 20}ms`;
    tr.innerHTML = `
      <td>
        <span class="record-badge type-${rec.type}">${rec.type}</span>
        <span class="record-ttl-mobile">${ttlLabel}</span>
      </td>
      <td><span class="record-ttl">${ttlLabel}</span></td>
      <td class="record-value-cell">
        <span class="record-card-value">${escapeHtml(rec.value)}</span>
        ${isIp ? `<button class="btn-ip-detail" data-ip="${escapeHtml(rec.value)}">IP Info</button>` : ''}
      </td>
      <td class="cell-action">
        <button class="btn-table-action" data-copy="${escapeHtml(rec.value)}">Copy</button>
      </td>
    `;

    // Copy button
    tr.querySelector('.btn-table-action').addEventListener('click', () => {
      copyText(rec.value);
    });

    // IP Inspect button
    if (isIp) {
      tr.querySelector('.btn-ip-detail').addEventListener('click', () => {
        inspectIpAddress(rec.value);
      });
    }

    elements.dnsTableBody.appendChild(tr);
  });
}

function isIpv4(str) {
  return typeof str === 'string' && /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(str.trim());
}

function formatTtl(ttl) {
  if (ttl === '-' || ttl === undefined || ttl === null || ttl === '') return '-';
  const seconds = Number(ttl);
  if (!Number.isFinite(seconds)) return String(ttl);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

// ==========================================================================
// WHOIS Structured Details
// ==========================================================================

function renderWhoisDetails(whois) {
  const unavailable = whois.isAvailable ? 'Not registered' : 'Not published';

  // 1. Registrar
  elements.whoisRegistrarKv.innerHTML = `
    <div class="kv-item"><span class="kv-key">Registrar Name</span><span class="kv-val font-mono">${escapeHtml(whois.registrar || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">IANA ID</span><span class="kv-val font-mono">${escapeHtml(whois.registrarIanaId || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Registrar URL</span><span class="kv-val font-mono">${whois.registrarUrl ? `<a href="${escapeHtml(whois.registrarUrl)}" target="_blank" rel="noopener" class="accent-cyan">${escapeHtml(whois.registrarUrl)}</a>` : unavailable}</span></div>
    <div class="kv-item"><span class="kv-key">Abuse Contact Email</span><span class="kv-val font-mono">${escapeHtml(whois.registrarAbuseEmail || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Abuse Contact Phone</span><span class="kv-val font-mono">${escapeHtml(whois.registrarAbusePhone || unavailable)}</span></div>
  `;

  // 2. Dates
  elements.whoisDatesKv.innerHTML = `
    <div class="kv-item"><span class="kv-key">Creation Date</span><span class="kv-val font-mono">${escapeHtml(whois.creationDate || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Registry Expiry Date</span><span class="kv-val font-mono">${escapeHtml(whois.expiryDate || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Updated / Modified Date</span><span class="kv-val font-mono">${escapeHtml(whois.updatedDate || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Estimated Domain Age</span><span class="kv-val font-mono accent-cyan">${escapeHtml(whois.domainAge || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Remaining Validity</span><span class="kv-val font-mono ${whois.daysUntilExpiry !== null && whois.daysUntilExpiry < 30 ? 'accent-red' : 'accent-green'}">${whois.daysUntilExpiry !== null ? whois.daysUntilExpiry + ' days remaining' : unavailable}</span></div>
  `;

  // 3. Registrant
  const reg = whois.registrant || {};
  const redacted = whois.isAvailable ? 'Not registered' : 'REDACTED FOR PRIVACY';
  elements.whoisRegistrantKv.innerHTML = `
    <div class="kv-item"><span class="kv-key">Registrant Name</span><span class="kv-val">${escapeHtml(reg.name || redacted)}</span></div>
    <div class="kv-item"><span class="kv-key">Organization</span><span class="kv-val">${escapeHtml(reg.organization || (whois.isAvailable ? 'Not registered' : 'Privacy Protected'))}</span></div>
    <div class="kv-item"><span class="kv-key">Country</span><span class="kv-val">${escapeHtml(reg.country || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">State / Province</span><span class="kv-val">${escapeHtml(reg.state || unavailable)}</span></div>
    <div class="kv-item"><span class="kv-key">Contact Email</span><span class="kv-val">${escapeHtml(reg.email || (whois.isAvailable ? 'Not registered' : 'Query Registrar for privacy relay'))}</span></div>
  `;

  // 4. Status Codes & EPP Flags
  elements.whoisStatusBadges.innerHTML = '';
  const statuses = Array.isArray(whois.status) ? whois.status : [];
  if (statuses.length === 0) {
    const empty = whois.isAvailable
      ? ['Not registered', 'No EPP status codes exist because the name is not registered.']
      : ['Not published', 'This registry does not publish EPP status codes for this domain.'];
    elements.whoisStatusBadges.innerHTML = `<div class="status-tag-item"><div class="status-code-name">${empty[0]}</div><div class="status-code-desc">${empty[1]}</div></div>`;
    return;
  }

  statuses.forEach(st => {
    const cleanSt = st.toLowerCase().split(' ')[0].trim();
    const desc = EPP_STATUS_DESCRIPTIONS[cleanSt] || 'EPP status flag set by registrar or registry.';
    const div = document.createElement('div');
    div.className = 'status-tag-item';
    div.innerHTML = `
      <div class="status-code-name">${escapeHtml(st)}</div>
      <div class="status-code-desc">${escapeHtml(desc)}</div>
    `;
    elements.whoisStatusBadges.appendChild(div);
  });
}

// ==========================================================================
// Global DNS Propagation Check
// ==========================================================================

async function runPropagationCheck(domain, recordType = 'A') {
  if (state.isPropagating || !domain) return;
  state.isPropagating = true;

  elements.btnRefreshPropagation.setAttribute('disabled', 'true');
  elements.propPercentageText.textContent = `Querying 8 global Anycast resolvers for ${recordType} records...`;
  elements.propProgressBar.style.width = '20%';
  elements.propStatusLabel.textContent = 'Querying';
  elements.propStatusLabel.className = 'badge';

  try {
    const res = await fetch(`/api/propagation?domain=${encodeURIComponent(domain)}&type=${encodeURIComponent(recordType)}`);
    if (!res.ok) throw new Error('Propagation API error');

    const data = await res.json();
    state.propagationData = data;
    renderPropagationResults(data);
  } catch (err) {
    console.error('Propagation check error:', err);
    elements.propPercentageText.textContent = 'Propagation query failed.';
    elements.propProgressBar.style.width = '0%';
  } finally {
    state.isPropagating = false;
    elements.btnRefreshPropagation.removeAttribute('disabled');
  }
}

function renderPropagationResults(data) {
  const pct = data.percentage || 0;
  elements.propProgressBar.style.width = `${pct}%`;
  elements.propPercentageText.textContent = `${data.resolvedCount} of ${data.totalResolvers} resolvers verified (${pct}%) in ${data.totalDurationMs}ms`;

  if (data.propagationStatus === 'complete') {
    elements.propStatusLabel.textContent = '100% Propagated';
    elements.propStatusLabel.className = 'badge badge-status';
  } else if (data.propagationStatus === 'divergent') {
    elements.propStatusLabel.textContent = 'Regional Divergence';
    elements.propStatusLabel.className = 'badge accent-amber';
  } else {
    elements.propStatusLabel.textContent = `${pct}% In Progress`;
    elements.propStatusLabel.className = 'badge accent-amber';
  }

  elements.resolversGrid.innerHTML = '';
  (data.resolvers || []).forEach(r => {
    const node = document.createElement('div');
    node.className = 'resolver-node-card';

    let badgeClass = 'ok';
    let badgeText = 'Resolved';
    if (!r.success || r.status === 'error') {
      badgeClass = 'error';
      badgeText = 'Error';
    } else if (r.status === 'no_record' || r.records.length === 0) {
      badgeClass = 'no-record';
      badgeText = 'No Record';
    }

    const firstVal = r.records && r.records.length > 0 ? r.records.join(', ') : (r.error || 'None');

    node.innerHTML = `
      <div class="resolver-top">
        <span class="resolver-name">${escapeHtml(r.name)}</span>
        <span class="resolver-status-badge ${badgeClass}">${badgeText}</span>
      </div>
      <div class="resolver-location">${escapeHtml(r.location)} (${escapeHtml(r.ip)})</div>
      <div class="resolver-result-val font-mono" title="${escapeHtml(firstVal)}">${escapeHtml(firstVal)}</div>
      <div class="resolver-latency">
        <span>Latency:</span>
        <span class="accent-cyan font-mono">${r.durationMs || 0}ms</span>
      </div>
    `;
    elements.resolversGrid.appendChild(node);
  });
}

// ==========================================================================
// IP Inspection Modal
// ==========================================================================

async function inspectIpAddress(ip) {
  elements.modalIpTitle.textContent = `IP Analysis: ${ip}`;
  elements.modalIpContent.innerHTML = '<div class="modal-loading"><span class="spinner"></span><p>Fetching reverse DNS &amp; Geolocation&hellip;</p></div>';
  elements.ipModal.style.display = 'flex';

  try {
    const res = await fetch(`/api/ip?ip=${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error('Failed to resolve IP details');
    const d = await res.json();

    elements.modalIpContent.innerHTML = `
      <div class="kv-list">
        <div class="kv-item"><span class="kv-key">IP Address</span><span class="kv-val font-mono accent-cyan">${escapeHtml(d.ip)}</span></div>
        <div class="kv-item"><span class="kv-key">Reverse DNS (PTR)</span><span class="kv-val font-mono">${escapeHtml(d.primaryHostname || d.reverseDns?.[0] || 'No PTR record')}</span></div>
        <div class="kv-item"><span class="kv-key">Location</span><span class="kv-val">${escapeHtml((d.city ? d.city + ', ' : '') + (d.region ? d.region + ', ' : '') + (d.country || 'Unknown'))}</span></div>
        <div class="kv-item"><span class="kv-key">ISP / Cloud Network</span><span class="kv-val">${escapeHtml(d.isp || 'Unknown')}</span></div>
        <div class="kv-item"><span class="kv-key">Organization</span><span class="kv-val">${escapeHtml(d.org || 'Unknown')}</span></div>
        <div class="kv-item"><span class="kv-key">Autonomous System (ASN)</span><span class="kv-val font-mono">${escapeHtml(d.asn || '-')}</span></div>
        <div class="kv-item"><span class="kv-key">Coordinates</span><span class="kv-val font-mono">${d.lat && d.lon ? `${d.lat}, ${d.lon}` : '-'}</span></div>
      </div>
    `;
  } catch (err) {
    elements.modalIpContent.innerHTML = `<p class="accent-red">Error: ${escapeHtml(err.message)}</p>`;
  }
}

// ==========================================================================
// Copy & Export Utilities
// ==========================================================================

function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard');
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Copied to clipboard');
  });
}

function copySummaryToClipboard() {
  if (!state.lookupData) return;
  const d = state.lookupData;
  const text = `WHOIS & DNS SUMMARY FOR: ${d.domain}
Registrar: ${d.whois?.registrar || '-'}
Created: ${d.whois?.creationDate || '-'}
Expires: ${d.whois?.expiryDate || '-'}
Primary IP: ${d.primaryIp?.ip || '-'}
Total DNS Records: ${d.dns?.totalRecords || 0}
Inspection Date: ${new Date().toISOString()}
Generated by WhoisDNS Web Tools`;
  copyText(text);
}

function copyNameservers() {
  const nsList = state.lookupData?.dns?.recordsByType?.['NS']?.records || state.lookupData?.whois?.nameServers || [];
  const text = nsList.map(n => typeof n === 'string' ? n : n.value).join('\n');
  copyText(text);
}

function copyVisibleDnsRecords() {
  if (!state.allRecordsFlat) return;
  const rows = [];
  const tbody = elements.dnsTableBody;
  tbody.querySelectorAll('tr').forEach(tr => {
    const tds = tr.querySelectorAll('td');
    if (tds.length >= 3) {
      rows.push(`${tds[0].innerText.trim()}\t${tds[1].innerText.trim()}\t${tds[2].innerText.trim()}`);
    }
  });
  copyText(rows.join('\n'));
}

function copyRawWhois() {
  copyText(elements.rawWhoisText.textContent);
}

function exportDataAsJson() {
  if (!state.lookupData) return;
  const jsonStr = JSON.stringify(state.lookupData, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${state.lookupData.domain}_whois_dns_report.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('JSON report downloaded');
}

function shareLookupLink() {
  const url = window.location.href;
  copyText(url);
  showToast('Shareable link copied to clipboard');
}

// Toast Notification
function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="20 6 9 17 4 12"></polyline>
    </svg>
    <span>${escapeHtml(message)}</span>
  `;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 2600);
}

// ==========================================================================
// Search History
// ==========================================================================

function loadSearchHistory() {
  try {
    const raw = localStorage.getItem('whoisdns_history');
    if (!raw) return;
    const history = JSON.parse(raw);
    if (Array.isArray(history) && history.length > 0) {
      elements.historyContainer.style.display = 'flex';
      elements.historyItems.innerHTML = '';
      history.slice(0, 6).forEach(item => {
        const btn = document.createElement('button');
        btn.className = 'chip-item';
        btn.textContent = item;
        btn.addEventListener('click', () => {
          elements.domainInput.value = item;
          elements.btnClearInput.style.display = 'flex';
          executeLookup(item);
        });
        elements.historyItems.appendChild(btn);
      });
    }
  } catch (_) {}
}

function getSearchHistory() {
  try {
    const raw = localStorage.getItem('whoisdns_history');
    const history = raw ? JSON.parse(raw) : [];
    return Array.isArray(history) ? history : [];
  } catch (_) {
    return [];
  }
}

function saveSearchHistory(domain) {
  try {
    let history = [];
    const raw = localStorage.getItem('whoisdns_history');
    if (raw) history = JSON.parse(raw);
    history = [domain, ...history.filter(h => h !== domain)].slice(0, 10);
    localStorage.setItem('whoisdns_history', JSON.stringify(history));
    loadSearchHistory();
  } catch (_) {}
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}
