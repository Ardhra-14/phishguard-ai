/**
 * PhishGuard AI - Warning Page Script
 * Reads query params from URL, fetches scan details if scan_id provided,
 * and handles "Go Back" and "Continue Anyway" actions.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = decodeURIComponent(urlParams.get('url') || '');
  const score = urlParams.get('score');
  const verdict = urlParams.get('verdict') || 'PHISHING';
  const scanId = urlParams.get('scan_id');
  const category = urlParams.get('category') || 'General';

  const targetUrlEl = document.getElementById('warn-target-url');
  const scoreEl = document.getElementById('warn-score');
  const verdictEl = document.getElementById('warn-verdict');
  const categoryEl = document.getElementById('warn-category');
  const reasonsEl = document.getElementById('warn-reasons');
  const btnGoBack = document.getElementById('btn-go-back');
  const btnContinue = document.getElementById('btn-continue-anyway');

  if (targetUrl) {
    targetUrlEl.textContent = targetUrl;
  } else {
    targetUrlEl.textContent = 'Unknown suspicious URL';
  }

  if (score !== null) {
    scoreEl.textContent = `${score} / 100`;
  }

  verdictEl.textContent = verdict.toUpperCase();
  categoryEl.textContent = category;

  // If scan_id provided, try to fetch detailed SHAP reasons from backend API
  if (scanId) {
    try {
      chrome.storage.local.get('phishguard_settings', async (data) => {
        const apiUrl = data?.phishguard_settings?.apiUrl || 'http://localhost:8000/api/v1/scan';
        const baseUrl = apiUrl.replace(/\/scan.*$/, '');
        const detailRes = await fetch(`${baseUrl}/scan/${scanId}`).catch(() => null);
        if (detailRes && detailRes.ok) {
          const detail = await detailRes.json();
          renderReasons(detail);
        }
      });
    } catch {
      // Fallback to defaults
    }
  }

  function renderReasons(detail) {
    if (!detail) return;
    const items = [];
    if (Array.isArray(detail.shap_json) && detail.shap_json.length > 0) {
      detail.shap_json.forEach((s) => {
        if (s.direction === 'phishing' || s.shap_value > 0) {
          items.push(s.label || s.feature);
        }
      });
    } else if (Array.isArray(detail.reasons) && detail.reasons.length > 0) {
      items.push(...detail.reasons);
    }

    if (detail.closest_brand && detail.visual_similarity > 0.6) {
      items.push(`Impersonation of brand: ${detail.closest_brand}`);
    }

    if (items.length > 0) {
      reasonsEl.innerHTML = '';
      items.slice(0, 4).forEach((reason) => {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsEl.appendChild(li);
      });
    }
  }

  // Go Back to Safety
  btnGoBack.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'chrome://newtab';
    }
  });

  // Continue Anyway
  btnContinue.addEventListener('click', () => {
    if (confirm('WARNING: Visiting this website may compromise your sensitive credentials or download malware. Proceed anyway?')) {
      chrome.runtime.sendMessage({ type: 'BYPASS_URL', url: targetUrl }, () => {
        window.location.href = targetUrl;
      });
    }
  });
});
