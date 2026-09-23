/**
 * PhishGuard AI - Options Script
 * Handles settings persistence, allowlist/blocklist configuration, and backend API testing.
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('settings-form');
  const optEnabled = document.getElementById('opt-enabled');
  const optLocalhost = document.getElementById('opt-localhost');
  const optFailsafe = document.getElementById('opt-failsafe');
  const optApiUrl = document.getElementById('opt-api-url');
  const optRiskUrl = document.getElementById('opt-risk-url');
  const optCacheTtl = document.getElementById('opt-cache-ttl');
  const optAllowlist = document.getElementById('opt-allowlist');
  const optBlocklist = document.getElementById('opt-blocklist');

  const btnTestApi = document.getElementById('btn-test-api');
  const apiStatusMsg = document.getElementById('api-status-msg');
  const btnClearCache = document.getElementById('btn-clear-cache');
  const btnResetStats = document.getElementById('btn-reset-stats');
  const btnResetDefaults = document.getElementById('btn-reset-defaults');
  const toast = document.getElementById('toast');

  const DEFAULT_CONFIG = {
    enabled: true,
    scanLocalhost: false,
    failSafeMode: 'warn',
    apiUrl: 'http://localhost:8000/api/v1/scan',
    websiteRiskUrl: 'http://localhost:5173/risk-score',
    cacheTtlSeconds: 1800,
    allowlist: [
      'google.com',
      'github.com',
      'microsoft.com',
      'stackoverflow.com',
      'wikipedia.org',
    ],
    blocklist: [],
  };

  // Load existing settings
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (res) => {
    const s = res?.settings || DEFAULT_CONFIG;
    populateForm(s);
  });

  function populateForm(s) {
    optEnabled.checked = s.enabled ?? true;
    optLocalhost.checked = s.scanLocalhost ?? false;
    optFailsafe.value = s.failSafeMode || 'warn';
    optApiUrl.value = s.apiUrl || DEFAULT_CONFIG.apiUrl;
    optRiskUrl.value = s.websiteRiskUrl || DEFAULT_CONFIG.websiteRiskUrl;
    optCacheTtl.value = s.cacheTtlSeconds || 1800;
    optAllowlist.value = (s.allowlist || []).join('\n');
    optBlocklist.value = (s.blocklist || []).join('\n');
  }

  function showToast(msg = 'Settings saved successfully!') {
    toast.textContent = msg;
    toast.classList.remove('hidden');
    setTimeout(() => {
      toast.classList.add('hidden');
    }, 3000);
  }

  // Save Settings
  form.addEventListener('submit', (e) => {
    e.preventDefault();

    const allowlist = optAllowlist.value
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    const blocklist = optBlocklist.value
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    const newSettings = {
      enabled: optEnabled.checked,
      scanLocalhost: optLocalhost.checked,
      failSafeMode: optFailsafe.value,
      apiUrl: optApiUrl.value.trim(),
      websiteRiskUrl: optRiskUrl.value.trim(),
      cacheTtlSeconds: parseInt(optCacheTtl.value, 10) || 1800,
      allowlist,
      blocklist,
    };

    chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings: newSettings }, (res) => {
      if (res?.success) {
        showToast('Settings saved successfully!');
      } else {
        alert('Failed to save settings: ' + (res?.message || 'unknown error'));
      }
    });
  });

  // Test API Connection
  btnTestApi.addEventListener('click', async () => {
    const testUrl = optApiUrl.value.trim();
    if (!testUrl) {
      alert('Please enter an API URL to test.');
      return;
    }

    apiStatusMsg.className = 'api-feedback';
    apiStatusMsg.textContent = 'Testing connection...';
    apiStatusMsg.style.display = 'block';

    try {
      // Test with a harmless sample URL
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(testUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        apiStatusMsg.className = 'api-feedback success';
        apiStatusMsg.textContent = `Connected successfully! (HTTP ${res.status}, Verdict: ${data.verdict || 'OK'})`;
      } else {
        apiStatusMsg.className = 'api-feedback error';
        apiStatusMsg.textContent = `Server responded with HTTP ${res.status}: ${res.statusText}`;
      }
    } catch (err) {
      apiStatusMsg.className = 'api-feedback error';
      apiStatusMsg.textContent = `Connection failed: ${err.message}. Is backend running on ${testUrl}?`;
    }
  });

  // Clear Cache
  btnClearCache.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear the scan cache? All URLs will be re-analyzed upon next visit.')) {
      chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }, (res) => {
        showToast('Scan cache cleared.');
      });
    }
  });

  // Reset Stats
  btnResetStats.addEventListener('click', () => {
    if (confirm('Reset threat counters and scan metrics to zero?')) {
      chrome.runtime.sendMessage({ type: 'RESET_STATS' }, (res) => {
        showToast('Statistics reset to zero.');
      });
    }
  });

  // Reset to Defaults
  btnResetDefaults.addEventListener('click', () => {
    if (confirm('Reset all settings to default values?')) {
      populateForm(DEFAULT_CONFIG);
      chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings: DEFAULT_CONFIG }, () => {
        showToast('Reset to default configuration.');
      });
    }
  });
});
