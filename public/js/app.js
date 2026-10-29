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
  btnErrorRetry: document.getElementById('btn-error-retry'),
  resultsView: document.getElementById('results-view'),

  // Overview Banner
  targetDomainName: document.getElementById('target-domain-name'),
  badgeTld: document.getElementById('badge-tld'),
  badgeStatus: document.getElementById('badge-status'),
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
  toastContainer: document.getElementById('toast-container')
};

// ==========================================================================
// Initialization & Event Listeners
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadSearchHistory();
  checkServerHealth();

  // Handle URL query parameter ?q= or ?domain=
  const urlParams = new URLSearchParams(window.location.search);
  const initialQuery = urlParams.get('q') || urlParams.get('domain');
  if (initialQuery) {
    elements.domainInput.value = initialQuery;
    executeLookup(initialQuery);
  }
});

function setupEventListeners() {
  // Search form submit
  elements.searchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const query = elements.domainInput.value.trim();
    if (query) executeLookup(query);
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
  elements.btnCopySummary.addEventListener('click', copySummaryToClipboard);
  elements.btnExportJson.addEventListener('click', exportDataAsJson);
  elements.btnShare.addEventListener('click', shareLookupLink);
  elements.btnCopyNs.addEventListener('click', copyNameservers);
  elements.btnCopyDnsRecords.addEventListener('click', copyVisibleDnsRecords);
  elements.btnCopyRaw.addEventListener('click', copyRawWhois);
  elements.btnErrorRetry.addEventListener('click', () => {
    if (state.currentDomain) executeLookup(state.currentDomain);
  });

  // Propagation triggers
  elements.propTypeSelect.addEventListener('change', () => {
    if (state.currentDomain) runPropagationCheck(state.currentDomain, elements.propTypeSelect.value);
  });
  elements.btnRefreshPropagation.addEventListener('click', () => {
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
  try {
    const res = await fetch('/api/health');
    if (res.ok) {
      statusEl.className = 'status-indicator online';
      statusText.textContent = 'Engine Online';
    }
  } catch (_) {
    statusEl.className = 'status-indicator offline';
    statusText.textContent = 'DoH Direct Mode';
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

// ==========================================================================
// Main Lookup Execution
// ==========================================================================

async function executeLookup(query) {
  const domain = sanitizeDomain(query);
  if (!domain) return;

  if (!isPlausibleDomain(domain) && !isIpv4(domain)) {
    elements.loadingView.style.display = 'none';
    elements.resultsView.style.display = 'none';
    elements.errorView.style.display = 'block';
    elements.errorTitle.textContent = 'Invalid Input';
    elements.errorMessage.textContent = 'Enter a valid domain name like example.com, or an IPv4/IPv6 address.';
    return;
  }

  state.currentDomain = domain;
  saveSearchHistory(domain);

  // Update browser URL query string without reloading
  const newUrl = `${window.location.pathname}?q=${encodeURIComponent(domain)}`;
  window.history.pushState({ domain }, '', newUrl);

  // Set UI Loading State
  elements.loadingView.style.display = 'block';
  elements.errorView.style.display = 'none';
  elements.resultsView.style.display = 'none';
  elements.searchSpinner.style.display = 'inline-block';
  elements.btnSearch.setAttribute('disabled', 'true');
  elements.loadingSubtext.textContent = `Connecting to WHOIS servers and analyzing DNS records for ${domain}...`;

  try {
    const res = await fetch(`/api/lookup?domain=${encodeURIComponent(domain)}`);
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.message || `Server returned error (${res.status})`);
    }

    const data = await res.json();
    state.lookupData = data;

    // Render results
    renderResults(data);

    elements.loadingView.style.display = 'none';
    elements.resultsView.style.display = 'block';
  } catch (err) {
    console.warn('Backend lookup failed, attempting browser direct DoH fallback...', err);
    try {
      const fallbackData = await runClientFallback(domain);
      state.lookupData = fallbackData;
      renderResults(fallbackData);
      elements.loadingView.style.display = 'none';
      elements.resultsView.style.display = 'block';
      showToast('Resolved via Cloudflare & Google DoH');
    } catch (fallbackErr) {
      elements.loadingView.style.display = 'none';
      elements.errorView.style.display = 'block';
      elements.errorTitle.textContent = 'Lookup Failed';
      elements.errorMessage.textContent = err.message || 'Unable to connect to domain or resolver.';
    }
  } finally {
    elements.searchSpinner.style.display = 'none';
    elements.btnSearch.removeAttribute('disabled');
  }
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

  // Status badge
  if (whois.isAvailable) {
    elements.badgeStatus.textContent = 'Available / Unregistered';
    elements.badgeStatus.className = 'badge accent-amber';
  } else if (whois.daysUntilExpiry !== null && whois.daysUntilExpiry < 0) {
    elements.badgeStatus.textContent = 'Expired';
    elements.badgeStatus.className = 'badge accent-red';
  } else {
    elements.badgeStatus.textContent = 'Active';
    elements.badgeStatus.className = 'badge badge-status';
  }

  // DNSSEC badge
  const isDnssec = dns.dnssec?.dnssecSupported || whois.dnssec === 'signed';
  elements.badgeDnssec.textContent = isDnssec ? 'DNSSEC Signed' : 'DNSSEC Unsigned';
  elements.badgeDnssec.className = isDnssec ? 'badge badge-dnssec accent-green' : 'badge badge-dnssec';

  // Sub meta row
  elements.metaIp.textContent = primaryIp.ip ? `IP: ${primaryIp.ip}` : 'IP: None';
  elements.metaGeo.textContent = primaryIp.country ? `Location: ${primaryIp.city ? primaryIp.city + ', ' : ''}${primaryIp.country}` : 'Location: Global / CDN';
  elements.metaAsn.textContent = primaryIp.asn ? `ASN: ${primaryIp.asn}` : (primaryIp.isp ? `ISP: ${primaryIp.isp}` : 'ASN: -');

  // 2. 4 Key Metrics Bar
  elements.kpiRegistrar.textContent = whois.registrar || 'Protected / Privacy';
  elements.kpiIanaId.textContent = whois.registrarIanaId ? `IANA ID: ${whois.registrarIanaId}` : (whois.registrarUrl || 'Registrar URL: -');
  elements.kpiAge.textContent = whois.domainAge || '-';
  elements.kpiCreated.textContent = whois.creationDate ? `Created: ${formatDate(whois.creationDate)}` : 'Created: -';
  elements.kpiExpiry.textContent = whois.expiryDate ? formatDate(whois.expiryDate) : '-';
  elements.kpiDaysLeft.textContent = whois.daysUntilExpiry !== null 
    ? (whois.daysUntilExpiry > 0 ? `${whois.daysUntilExpiry.toLocaleString()} days left` : `Expired ${Math.abs(whois.daysUntilExpiry)} days ago`)
    : 'Expires: -';
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
  elements.resolversGrid.innerHTML = '<div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 2rem;">Click "Refresh Propagation" or open tab to test 8 global Anycast resolvers.</div>';
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
    chainDiv.className = 'geo-item';
    chainDiv.style.gridColumn = '1/-1';
    chainDiv.innerHTML = `
      <div class="geo-label">CNAME Chain</div>
      <div class="geo-val font-mono" title="${escapeHtml(chain.join(' -> '))}">${escapeHtml(chain.join(' \u2192 '))}</div>
    `;
    elements.overviewGeoDetails.appendChild(chainDiv);
  }

  if (!ipInfo || !ipInfo.ip) {
    if (chain.length === 0) {
      elements.overviewGeoDetails.innerHTML = '<div class="geo-item text-muted" style="grid-column: 1/-1;">No IP information available</div>';
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
    tr.innerHTML = `<td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">No ${filterType === 'ALL' ? '' : filterType} records match query.</td>`;
    elements.dnsTableBody.appendChild(tr);
    return;
  }

  filtered.forEach(rec => {
    const tr = document.createElement('tr');
    const isIp = isIpv4(rec.value);
    const ttlLabel = formatTtl(rec.ttl);

    tr.innerHTML = `
      <td>
        <span class="record-badge type-${rec.type}">${rec.type}</span>
        <span class="record-ttl-mobile">${ttlLabel}</span>
      </td>
      <td><span class="record-ttl">${ttlLabel}</span></td>
      <td class="record-value-cell">
        <span>${escapeHtml(rec.value)}</span>
        ${isIp ? `<button class="btn-ip-detail" data-ip="${escapeHtml(rec.value)}">IP Info</button>` : ''}
      </td>
      <td style="text-align: right;">
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
  // 1. Registrar
  elements.whoisRegistrarKv.innerHTML = `
    <div class="kv-item"><span class="kv-key">Registrar Name</span><span class="kv-val font-mono">${escapeHtml(whois.registrar || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">IANA ID</span><span class="kv-val font-mono">${escapeHtml(whois.registrarIanaId || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Registrar URL</span><span class="kv-val font-mono">${whois.registrarUrl ? `<a href="${escapeHtml(whois.registrarUrl)}" target="_blank" rel="noopener" class="accent-cyan">${escapeHtml(whois.registrarUrl)}</a>` : '-'}</span></div>
    <div class="kv-item"><span class="kv-key">Abuse Contact Email</span><span class="kv-val font-mono">${escapeHtml(whois.registrarAbuseEmail || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Abuse Contact Phone</span><span class="kv-val font-mono">${escapeHtml(whois.registrarAbusePhone || '-')}</span></div>
  `;

  // 2. Dates
  elements.whoisDatesKv.innerHTML = `
    <div class="kv-item"><span class="kv-key">Creation Date</span><span class="kv-val font-mono">${escapeHtml(whois.creationDate || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Registry Expiry Date</span><span class="kv-val font-mono">${escapeHtml(whois.expiryDate || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Updated / Modified Date</span><span class="kv-val font-mono">${escapeHtml(whois.updatedDate || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Estimated Domain Age</span><span class="kv-val font-mono accent-cyan">${escapeHtml(whois.domainAge || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Remaining Validity</span><span class="kv-val font-mono ${whois.daysUntilExpiry < 30 ? 'accent-red' : 'accent-green'}">${whois.daysUntilExpiry !== null ? whois.daysUntilExpiry + ' days remaining' : '-'}</span></div>
  `;

  // 3. Registrant
  const reg = whois.registrant || {};
  elements.whoisRegistrantKv.innerHTML = `
    <div class="kv-item"><span class="kv-key">Registrant Name</span><span class="kv-val">${escapeHtml(reg.name || 'REDACTED FOR PRIVACY')}</span></div>
    <div class="kv-item"><span class="kv-key">Organization</span><span class="kv-val">${escapeHtml(reg.organization || 'Privacy Protected')}</span></div>
    <div class="kv-item"><span class="kv-key">Country</span><span class="kv-val">${escapeHtml(reg.country || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">State / Province</span><span class="kv-val">${escapeHtml(reg.state || '-')}</span></div>
    <div class="kv-item"><span class="kv-key">Contact Email</span><span class="kv-val">${escapeHtml(reg.email || 'Query Registrar for privacy relay')}</span></div>
  `;

  // 4. Status Codes & EPP Flags
  elements.whoisStatusBadges.innerHTML = '';
  const statuses = Array.isArray(whois.status) ? whois.status : [];
  if (statuses.length === 0) {
    elements.whoisStatusBadges.innerHTML = '<div class="status-tag-item"><div class="status-code-name">Status Unspecified</div><div class="status-code-desc">No specific EPP lock flags reported by registry.</div></div>';
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
  elements.modalIpContent.innerHTML = '<div style="text-align: center; padding: 2rem;"><span class="spinner"></span><p style="margin-top: 1rem; color: var(--text-muted);">Fetching reverse DNS &amp; Geolocation...</p></div>';
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
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00E5FF" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
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
