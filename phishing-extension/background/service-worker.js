/**
 * PhishGuard AI - Background Service Worker (Manifest V3)
 * Orchestrates navigation interception, backend scanning, caching, loop prevention, and tab management.
 */

import {
  shouldIgnoreUrl,
  isOwnApplicationUrl,
  isAllowlisted,
  isBlocklisted,
  normalizeUrl,
  extractDomain,
  buildRedirectUrl,
  safeParseUrl,
} from '../utils/url-utils.js';

import { scanCache } from '../utils/cache.js';
import { checkUrlWithBackend, DEFAULT_API_URL } from '../utils/api.js';

// Default configuration settings
const DEFAULT_SETTINGS = {
  enabled: true,
  apiUrl: DEFAULT_API_URL,
  websiteRiskUrl: 'http://localhost:5173/risk-score',
  cacheTtlSeconds: 1800, // 30 minutes
  scanLocalhost: false,
  failSafeMode: 'warn', // 'warn' | 'allow' | 'block'
  interceptionMode: 'fast', // 'fast' | 'strict'
  allowlist: [
    'google.com',
    'github.com',
    'microsoft.com',
    'stackoverflow.com',
    'wikipedia.org',
  ],
  blocklist: [],
};

// Runtime in-memory state
let currentSettings = { ...DEFAULT_SETTINGS };
let stats = {
  threatsBlocked: 0,
  totalScans: 0,
  safeSites: 0,
  lastScan: null,
};

// Set of URLs temporarily bypassed by user clicking "Continue Anyway" during this session
const sessionBypassedUrls = new Set();

// Active scans tracking (to avoid concurrent duplicate scans for the same tab/url)
const activeScans = new Map(); // tabId -> { url, controller }

// Tab states for popup inspection
const tabScanStates = new Map(); // tabId -> ScanResult

// ============================================================================
// Initialization & Settings Management
// ============================================================================

async function init() {
  console.log('[PhishGuard AI] Service Worker initializing...');

  try {
    const data = await chrome.storage.local.get(['phishguard_settings', 'phishguard_stats']);

    if (data.phishguard_settings) {
      currentSettings = { ...DEFAULT_SETTINGS, ...data.phishguard_settings };
    } else {
      await chrome.storage.local.set({ phishguard_settings: DEFAULT_SETTINGS });
    }

    if (data.phishguard_stats) {
      stats = { ...stats, ...data.phishguard_stats };
    } else {
      await chrome.storage.local.set({ phishguard_stats: stats });
    }
  } catch (err) {
    console.error('[PhishGuard AI] Failed to load stored settings:', err);
  }

  // Setup periodic cache maintenance alarm
  try {
    await chrome.alarms.create('phishguard_prune_cache', { periodInMinutes: 15 });
  } catch (e) {
    // Alarms permission fallback
  }

  updateExtensionBadge();
  console.log('[PhishGuard AI] Initialized successfully. Protection:', currentSettings.enabled ? 'ON' : 'OFF');
}

chrome.runtime.onInstalled.addListener(() => {
  init();
});

chrome.runtime.onStartup.addListener(() => {
  init();
});

// Periodic alarm listener
if (chrome.alarms?.onAlarm) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'phishguard_prune_cache') {
      scanCache.prune();
    }
  });
}

async function saveSettings(newSettings) {
  currentSettings = { ...currentSettings, ...newSettings };
  await chrome.storage.local.set({ phishguard_settings: currentSettings });
  updateExtensionBadge();
  console.log('[PhishGuard AI] Settings updated:', currentSettings);
}

async function updateStats(updater) {
  updater(stats);
  try {
    await chrome.storage.local.set({ phishguard_stats: stats });
  } catch (e) {
    // Ignore storage errors
  }
  updateExtensionBadge();
}

function updateExtensionBadge() {
  if (!currentSettings.enabled) {
    chrome.action.setBadgeText({ text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#64748b' }); // slate
    return;
  }

  if (stats.threatsBlocked > 0) {
    chrome.action.setBadgeText({ text: String(stats.threatsBlocked) });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); // red
  } else {
    chrome.action.setBadgeText({ text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ color: '#10b981' }); // green
  }
}

// ============================================================================
// Core Navigation Interception Logic
// ============================================================================

/**
 * Handles navigation before page loads (webNavigation.onBeforeNavigate)
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept main frame (top-level tab navigation)
  if (details.frameId !== 0) return;
  if (!currentSettings.enabled) return;

  const url = details.url;
  const tabId = details.tabId;

  // 1. Filter out browser internal / ignored URLs
  if (shouldIgnoreUrl(url, currentSettings)) {
    return;
  }

  // 2. Loop Prevention: never scan backend API or website risk-score URLs
  if (isOwnApplicationUrl(url, currentSettings.apiUrl, currentSettings.websiteRiskUrl)) {
    console.log('[PhishGuard AI] Internal application domain accessed (loop prevention):', url);
    return;
  }

  // 3. User allowlist check
  if (isAllowlisted(url, currentSettings.allowlist)) {
    console.log('[PhishGuard AI] Allowlisted site bypassed:', url);
    tabScanStates.set(tabId, {
      url,
      domain: extractDomain(url),
      verdict: 'SAFE',
      score: 0,
      riskLevel: 'LOW',
      reasons: ['Domain is in user allowlist'],
    });
    return;
  }

  // 4. Session user-bypass check ("Continue Anyway")
  const normalized = normalizeUrl(url);
  const domain = extractDomain(url);
  if (sessionBypassedUrls.has(normalized) || sessionBypassedUrls.has(domain)) {
    console.log('[PhishGuard AI] Session bypass active for:', url);
    return;
  }

  // 5. User custom blocklist check
  if (isBlocklisted(url, currentSettings.blocklist)) {
    console.warn('[PhishGuard AI] Blocklisted URL detected:', url);
    const mockBlocked = {
      scan_id: 'blocklist-' + Date.now(),
      score: 100,
      verdict: 'PHISHING',
      riskLevel: 'HIGH',
      isPhishing: true,
      reasons: ['Domain matches your custom blocklist'],
    };
    executeBlockRedirect(tabId, url, mockBlocked);
    return;
  }

  // 6. Check Cache
  const cached = await scanCache.get(url);
  if (cached) {
    console.log('[PhishGuard AI] Cache hit for:', url, 'Verdict:', cached.verdict, 'Score:', cached.score);
    tabScanStates.set(tabId, cached);

    if (cached.isDangerous || cached.verdict === 'PHISHING' || cached.verdict === 'SUSPICIOUS') {
      executeBlockRedirect(tabId, url, cached);
      return;
    }

    // Cached safe — allow navigation unimpeded
    return;
  }

  // 7. Cache Miss -> Dispatch scanning
  console.log('[PhishGuard AI] Cache miss. Initiating backend inspection for:', url);
  dispatchScan(tabId, url);
});

/**
 * Dispatches scan to the backend API and handles the result
 */
async function dispatchScan(tabId, url) {
  // Cancel previous active scan for this tab if running
  if (activeScans.has(tabId)) {
    const prev = activeScans.get(tabId);
    if (prev.url !== url && prev.controller) {
      prev.controller.abort();
    }
  }

  const controller = new AbortController();
  activeScans.set(tabId, { url, controller });

  // Update tab status to scanning
  tabScanStates.set(tabId, {
    url,
    domain: extractDomain(url),
    verdict: 'SCANNING',
    score: null,
    riskLevel: 'UNKNOWN',
    reasons: ['Scanning website with PhishGuard AI...'],
  });

  try {
    const scanResponse = await checkUrlWithBackend(url, {
      apiUrl: currentSettings.apiUrl,
      timeoutMs: 6000,
    });

    activeScans.delete(tabId);

    // Handle API Error / Unavailable
    if (!scanResponse.success) {
      handleApiFailure(tabId, url, scanResponse);
      return;
    }

    // Process scan result
    console.log(
      `[PhishGuard AI] Scanned: ${url} | Verdict: ${scanResponse.verdict} | Score: ${scanResponse.score} | Category: ${scanResponse.category}`
    );

    // Update Cache
    await scanCache.set(url, scanResponse, currentSettings.cacheTtlSeconds);

    // Save tab scan state
    tabScanStates.set(tabId, scanResponse);

    if (scanResponse.isDangerous || scanResponse.verdict === 'PHISHING' || scanResponse.verdict === 'SUSPICIOUS') {
      // SUSPICIOUS / PHISHING -> Block & Redirect
      await updateStats((s) => {
        s.totalScans++;
        s.threatsBlocked++;
        s.lastScan = {
          url,
          domain: scanResponse.domain,
          score: scanResponse.score,
          verdict: scanResponse.verdict,
          time: Date.now(),
        };
      });

      executeBlockRedirect(tabId, url, scanResponse);
    } else {
      // SAFE -> Allow normal browsing
      await updateStats((s) => {
        s.totalScans++;
        s.safeSites++;
        s.lastScan = {
          url,
          domain: scanResponse.domain,
          score: scanResponse.score,
          verdict: scanResponse.verdict,
          time: Date.now(),
        };
      });
      console.log('[PhishGuard AI] URL verified SAFE. Page allowed to proceed normally.');
    }
  } catch (err) {
    activeScans.delete(tabId);
    console.error('[PhishGuard AI] Scan exception for:', url, err);
  }
}

/**
 * Handles API timeouts or connection drops gracefully according to failSafeMode
 */
function handleApiFailure(tabId, url, errorDetails) {
  console.warn('[PhishGuard AI] Backend unreachable:', errorDetails.message);

  const errorResult = {
    url,
    domain: extractDomain(url),
    verdict: 'UNVERIFIED',
    score: 0,
    riskLevel: 'UNKNOWN',
    reasons: ['Unable to verify this website. Backend detection service is unreachable.'],
    error: errorDetails,
  };

  tabScanStates.set(tabId, errorResult);

  if (currentSettings.failSafeMode === 'block') {
    // High-security strict mode: block if cannot verify
    executeBlockRedirect(tabId, url, {
      scan_id: 'offline-' + Date.now(),
      score: 50,
      verdict: 'SUSPICIOUS',
      riskLevel: 'MEDIUM',
      reasons: ['High security policy: Blocked unverified URL because detection API is offline.'],
    });
  } else if (currentSettings.failSafeMode === 'warn') {
    // Notify via badge / popup
    chrome.action.setBadgeText({ text: '?' });
    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' }); // amber
  }
  // If 'allow', do nothing (permissive fail-open)
}

/**
 * Intercepts / redirects the tab away from the malicious page to the Risk Score page
 */
function executeBlockRedirect(tabId, originalUrl, scanResult) {
  console.warn(`[PhishGuard AI] 🛑 INTERCEPTING THREAT: ${originalUrl} -> Redirecting to Risk Score page.`);

  const redirectUrl = buildRedirectUrl(
    currentSettings.websiteRiskUrl,
    scanResult,
    originalUrl
  );

  // Update tab navigation immediately
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;

    // Check if the tab is already on the redirect target to prevent any loop
    if (tab.url && tab.url.startsWith(currentSettings.websiteRiskUrl)) {
      return;
    }

    chrome.tabs.update(tabId, { url: redirectUrl }, (updatedTab) => {
      if (chrome.runtime.lastError) {
        console.error('[PhishGuard AI] Failed to redirect tab:', chrome.runtime.lastError.message);
      } else {
        console.log('[PhishGuard AI] Tab successfully redirected to:', redirectUrl);
      }
    });
  });
}

// ============================================================================
// Tab State Tracking & Badge Sync
// ============================================================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const scan = tabScanStates.get(tabId);
    if (scan && scan.verdict === 'PHISHING') {
      chrome.action.setBadgeText({ tabId, text: '!' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' });
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScanStates.delete(tabId);
  activeScans.delete(tabId);
});

// ============================================================================
// Message Handling (Popup, Options, Warning Page)
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const type = message?.type;

  switch (type) {
    case 'GET_CURRENT_TAB_STATUS': {
      // Find active tab and return its scan result
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) {
          sendResponse({ success: false, message: 'No active tab found' });
          return;
        }
        const activeTab = tabs[0];
        const state = tabScanStates.get(activeTab.id) || {
          url: activeTab.url,
          domain: extractDomain(activeTab.url),
          verdict: shouldIgnoreUrl(activeTab.url, currentSettings) ? 'IGNORED' : 'PENDING',
          score: null,
          riskLevel: 'LOW',
        };

        sendResponse({
          success: true,
          tab: activeTab,
          scan: state,
          enabled: currentSettings.enabled,
          stats,
        });
      });
      return true; // Keep message channel open for async response
    }

    case 'TOGGLE_PROTECTION': {
      saveSettings({ enabled: !currentSettings.enabled }).then(() => {
        sendResponse({ success: true, enabled: currentSettings.enabled });
      });
      return true;
    }

    case 'MANUAL_SCAN_URL': {
      const url = message.url;
      checkUrlWithBackend(url, { apiUrl: currentSettings.apiUrl }).then(async (res) => {
        if (res?.success) {
          await scanCache.set(url, res, currentSettings.cacheTtlSeconds);
          if (sender.tab?.id) {
            tabScanStates.set(sender.tab.id, res);
          }
        }
        sendResponse(res);
      });
      return true;
    }

    case 'GET_SETTINGS': {
      sendResponse({ success: true, settings: currentSettings });
      break;
    }

    case 'SAVE_SETTINGS': {
      saveSettings(message.settings).then(() => {
        sendResponse({ success: true, settings: currentSettings });
      });
      return true;
    }

    case 'GET_STATS': {
      sendResponse({ success: true, stats });
      break;
    }

    case 'RESET_STATS': {
      stats = { threatsBlocked: 0, totalScans: 0, safeSites: 0, lastScan: null };
      chrome.storage.local.set({ phishguard_stats: stats }).then(() => {
        updateExtensionBadge();
        sendResponse({ success: true, stats });
      });
      return true;
    }

    case 'CLEAR_CACHE': {
      scanCache.clear().then(() => {
        sendResponse({ success: true });
      });
      return true;
    }

    case 'BYPASS_URL': {
      const url = message.url;
      if (url) {
        sessionBypassedUrls.add(normalizeUrl(url));
        sessionBypassedUrls.add(extractDomain(url));
        console.log('[PhishGuard AI] User bypassed threat for session:', url);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, message: 'Missing URL' });
      }
      break;
    }

    default:
      sendResponse({ success: false, message: `Unknown message type: ${type}` });
  }

  return false;
});
