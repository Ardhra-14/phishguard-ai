/**
 * PhishGuard AI - Popup Script
 * Interacts with background service worker to display live tab analysis and metrics.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('protection-toggle');
  const statusBanner = document.getElementById('status-banner');
  const statusText = document.getElementById('status-text');
  const currentDomainEl = document.getElementById('current-domain');
  const scoreCircle = document.getElementById('score-circle');
  const scoreVal = document.getElementById('score-value');
  const verdictBadge = document.getElementById('verdict-badge');
  const riskLevelEl = document.getElementById('risk-level');
  const siteCategoryEl = document.getElementById('site-category');
  const reasonsContainer = document.getElementById('reasons-container');
  const reasonsList = document.getElementById('reasons-list');
  const threatsBlockedEl = document.getElementById('stat-threats-blocked');
  const totalScansEl = document.getElementById('stat-total-scans');
  const btnRescan = document.getElementById('btn-rescan');
  const btnDashboard = document.getElementById('btn-open-dashboard');
  const btnSettings = document.getElementById('btn-open-settings');

  let activeTabUrl = null;

  // Load current tab state from service worker
  async function loadStatus() {
    try {
      chrome.runtime.sendMessage({ type: 'GET_CURRENT_TAB_STATUS' }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
          currentDomainEl.textContent = 'Unable to read tab';
          return;
        }

        const { tab, scan, enabled, stats } = response;
        activeTabUrl = tab?.url;

        // Protection toggle state
        toggle.checked = !!enabled;
        updateProtectionBanner(enabled);

        // Stats
        if (stats) {
          threatsBlockedEl.textContent = stats.threatsBlocked || 0;
          totalScansEl.textContent = stats.totalScans || 0;
        }

        // Domain
        const displayDomain = scan?.domain || (tab?.url ? new URL(tab.url).hostname : 'Unknown');
        currentDomainEl.textContent = displayDomain;

        // Render Scan Result
        renderScanDetails(scan);
      });
    } catch (e) {
      console.error('[Popup] Load status error:', e);
    }
  }

  function updateProtectionBanner(enabled) {
    if (enabled) {
      statusBanner.className = 'status-banner banner-active';
      statusText.textContent = 'Protection Active';
    } else {
      statusBanner.className = 'status-banner banner-disabled';
      statusText.textContent = 'Protection Paused';
    }
  }

  function renderScanDetails(scan) {
    if (!scan) return;

    const verdict = (scan.verdict || 'PENDING').toUpperCase();
    const score = typeof scan.score === 'number' ? scan.score : null;

    // Reset classes
    scoreCircle.className = 'score-circle';
    verdictBadge.className = 'badge';
    riskLevelEl.className = 'font-bold';

    if (verdict === 'PHISHING') {
      scoreCircle.classList.add('score-phishing');
      verdictBadge.classList.add('badge-phishing');
      riskLevelEl.classList.add('text-danger');
      verdictBadge.textContent = 'PHISHING';
      riskLevelEl.textContent = 'CRITICAL';
    } else if (verdict === 'SUSPICIOUS') {
      scoreCircle.classList.add('score-suspicious');
      verdictBadge.classList.add('badge-suspicious');
      riskLevelEl.classList.add('text-warning');
      verdictBadge.textContent = 'SUSPICIOUS';
      riskLevelEl.textContent = 'ELEVATED';
    } else if (verdict === 'SAFE') {
      scoreCircle.classList.add('score-safe');
      verdictBadge.classList.add('badge-safe');
      riskLevelEl.classList.add('text-safe');
      verdictBadge.textContent = 'SAFE';
      riskLevelEl.textContent = 'LOW';
    } else if (verdict === 'SCANNING') {
      scoreCircle.classList.add('score-unknown');
      verdictBadge.classList.add('badge-suspicious');
      riskLevelEl.classList.add('text-warning');
      verdictBadge.textContent = 'SCANNING...';
      riskLevelEl.textContent = 'ANALYZING';
    } else {
      // Ignored / System / Local
      scoreCircle.classList.add('score-unknown');
      verdictBadge.classList.add('badge-safe');
      riskLevelEl.classList.add('text-safe');
      verdictBadge.textContent = 'INTERNAL';
      riskLevelEl.textContent = 'N/A';
    }

    scoreVal.textContent = score !== null ? score : '--';
    siteCategoryEl.textContent = scan.category || 'General';

    // Reasons
    if (Array.isArray(scan.reasons) && scan.reasons.length > 0) {
      reasonsContainer.classList.remove('hidden');
      reasonsList.innerHTML = '';
      scan.reasons.slice(0, 3).forEach((r) => {
        const li = document.createElement('li');
        li.textContent = r;
        reasonsList.appendChild(li);
      });
    } else {
      reasonsContainer.classList.add('hidden');
    }
  }

  // Toggle protection event
  toggle.addEventListener('change', () => {
    chrome.runtime.sendMessage({ type: 'TOGGLE_PROTECTION' }, (res) => {
      if (res && res.success) {
        updateProtectionBanner(res.enabled);
      }
    });
  });

  // Rescan button
  btnRescan.addEventListener('click', () => {
    if (!activeTabUrl) return;
    renderScanDetails({ verdict: 'SCANNING', score: null });
    chrome.runtime.sendMessage({ type: 'MANUAL_SCAN_URL', url: activeTabUrl }, (res) => {
      if (res) {
        renderScanDetails(res);
      }
    });
  });

  // Open web dashboard
  btnDashboard.addEventListener('click', () => {
    chrome.storage.local.get('phishguard_settings', (data) => {
      const target = data?.phishguard_settings?.websiteRiskUrl || 'http://localhost:5173/';
      const home = target.replace(/\/risk-score.*$/, '');
      chrome.tabs.create({ url: home });
    });
  });

  // Open settings
  btnSettings.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      chrome.tabs.create({ url: chrome.runtime.getURL('options/options.html') });
    }
  });

  // Initial load
  loadStatus();
});
