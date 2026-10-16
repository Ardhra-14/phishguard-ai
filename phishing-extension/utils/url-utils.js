/**
 * URL Utilities for PhishGuard AI Extension
 * Provides robust URL parsing, validation, loop prevention, and allowlist matching.
 */

// Protocols that cannot and should not be inspected
const IGNORED_PROTOCOLS = new Set([
  'chrome:',
  'chrome-extension:',
  'chrome-search:',
  'edge:',
  'about:',
  'file:',
  'view-source:',
  'data:',
  'blob:',
  'devtools:',
  'javascript:',
  'mailto:',
  'tel:',
]);

/**
 * Checks if a string is a valid HTTP/HTTPS URL
 * @param {string} urlString
 * @returns {boolean}
 */
export function isValidUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') return false;
  try {
    const parsed = new URL(urlString.trim());
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Parses a URL safely without throwing
 * @param {string} urlString
 * @returns {URL|null}
 */
export function safeParseUrl(urlString) {
  if (!urlString) return null;
  try {
    return new URL(urlString.trim());
  } catch {
    return null;
  }
}

/**
 * Checks if the URL protocol should be completely ignored
 * @param {string} urlString
 * @returns {boolean}
 */
export function isIgnoredProtocol(urlString) {
  const parsed = safeParseUrl(urlString);
  if (!parsed) return true;
  return IGNORED_PROTOCOLS.has(parsed.protocol);
}

/**
 * Checks if the URL is localhost or a loopback address
 * @param {string} urlString
 * @returns {boolean}
 */
export function isLocalhost(urlString) {
  const parsed = safeParseUrl(urlString);
  if (!parsed) return false;
  const host = parsed.hostname.toLowerCase();
  return (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '[::1]' ||
    host === '0.0.0.0' ||
    host.endsWith('.local')
  );
}

/**
 * Determines whether a URL should be excluded from scanning
 * @param {string} urlString
 * @param {Object} settings
 * @returns {boolean}
 */
export function shouldIgnoreUrl(urlString, settings = {}) {
  if (!urlString || typeof urlString !== 'string') return true;

  const parsed = safeParseUrl(urlString);
  if (!parsed) return true;

  // Ignore non-http/https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return true;
  }

  // Ignore browser internal extension/store URLs
  const host = parsed.hostname.toLowerCase();
  if (
    host === 'chrome.google.com' ||
    host === 'chromewebstore.google.com' ||
    host === 'newtab'
  ) {
    return true;
  }

  // Check localhost option
  if (!settings.scanLocalhost && isLocalhost(urlString)) {
    return true;
  }

  return false;
}

/**
 * Normalizes a URL for consistent caching and lookup:
 * - Trims whitespace
 * - Drops hash/fragments
 * - Lowercases hostname
 * - Standardizes slashes
 * @param {string} urlString
 * @returns {string}
 */
export function normalizeUrl(urlString) {
  const parsed = safeParseUrl(urlString);
  if (!parsed) return (urlString || '').trim();

  // Drop fragment hash
  parsed.hash = '';

  // Remove default ports (80 for HTTP, 443 for HTTPS)
  if (
    (parsed.protocol === 'http:' && parsed.port === '80') ||
    (parsed.protocol === 'https:' && parsed.port === '443')
  ) {
    parsed.port = '';
  }

  // Standardize trailing slash on empty paths
  let normalized = parsed.toString();
  if (normalized.endsWith('/') && parsed.pathname === '/' && !parsed.search) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

/**
 * Extracts normalized hostname
 * @param {string} urlString
 * @returns {string}
 */
export function extractDomain(urlString) {
  const parsed = safeParseUrl(urlString);
  return parsed ? parsed.hostname.toLowerCase() : '';
}

/**
 * Helper to match a host against an allowlist pattern
 * Supports: exact match ("example.com"), wildcard ("*.example.com" or ".example.com")
 * @param {string} host
 * @param {string} pattern
 * @returns {boolean}
 */
function hostMatches(host, pattern) {
  if (!host || !pattern) return false;
  host = host.toLowerCase().trim();
  pattern = pattern.toLowerCase().trim();

  // Strip protocol if user mistakenly pasted "https://example.com"
  if (pattern.includes('://')) {
    try {
      pattern = new URL(pattern).hostname.toLowerCase();
    } catch {
      // ignore
    }
  }

  // Strip leading wildcard or dot
  if (pattern.startsWith('*.')) {
    const root = pattern.slice(2);
    return host === root || host.endsWith('.' + root);
  }
  if (pattern.startsWith('.')) {
    const root = pattern.slice(1);
    return host === root || host.endsWith('.' + root);
  }

  return host === pattern || host.endsWith('.' + pattern);
}

/**
 * Checks if a host is in the allowlist
 * @param {string} urlString
 * @param {string[]} allowlist
 * @returns {boolean}
 */
export function isAllowlisted(urlString, allowlist = []) {
  const host = extractDomain(urlString);
  if (!host || !Array.isArray(allowlist)) return false;
  return allowlist.some((item) => hostMatches(host, item));
}

/**
 * Checks if a host is in the blocklist
 * @param {string} urlString
 * @param {string[]} blocklist
 * @returns {boolean}
 */
export function isBlocklisted(urlString, blocklist = []) {
  const host = extractDomain(urlString);
  if (!host || !Array.isArray(blocklist)) return false;
  return blocklist.some((item) => hostMatches(host, item));
}

/**
 * Checks if the URL belongs to PhishGuard's own backend or frontend website
 * CRITICAL FOR REDIRECT LOOP PREVENTION.
 * @param {string} urlString
 * @param {string} backendApiUrl
 * @param {string} websiteRiskUrl
 * @returns {boolean}
 */
export function isOwnApplicationUrl(urlString, backendApiUrl, websiteRiskUrl) {
  const parsed = safeParseUrl(urlString);
  if (!parsed) return false;

  const currentHost = parsed.host.toLowerCase(); // includes port if non-default

  // Check backend API host
  const backendParsed = safeParseUrl(backendApiUrl);
  if (backendParsed && backendParsed.host.toLowerCase() === currentHost) {
    return true;
  }

  // Check frontend website / risk-score host
  const websiteParsed = safeParseUrl(websiteRiskUrl);
  if (websiteParsed && websiteParsed.host.toLowerCase() === currentHost) {
    return true;
  }

  // Also check standard known PhishGuard local endpoints
  if (
    currentHost === 'localhost:8000' ||
    currentHost === '127.0.0.1:8000' ||
    currentHost === 'localhost:5173' ||
    currentHost === '127.0.0.1:5173' ||
    currentHost === 'localhost:3000' ||
    currentHost === '127.0.0.1:3000'
  ) {
    return true;
  }

  return false;
}

/**
 * Constructs the safe redirect URL for a detected threat.
 * Prefers scan_id route (/risk-score/<scan_id>) and includes query parameters
 * for maximum compatibility with both backend-driven and client-side warning pages.
 * @param {string} baseWarningUrl - e.g. "http://localhost:5173/risk-score"
 * @param {Object} scanResult
 * @param {string} originalUrl
 * @returns {string}
 */
export function buildRedirectUrl(baseWarningUrl, scanResult = {}, originalUrl = '') {
  let targetUrl = baseWarningUrl ? baseWarningUrl.trim() : 'http://localhost:5173/risk-score';

  // Normalize base URL
  if (targetUrl.endsWith('/')) {
    targetUrl = targetUrl.slice(0, -1);
  }

  const scanId = scanResult.scan_id || scanResult.scanId || '';
  const score = scanResult.score ?? scanResult.riskScore ?? 0;
  const verdict = scanResult.verdict || (scanResult.isPhishing ? 'PHISHING' : 'SUSPICIOUS');

  // If scanId is present, we form: ${baseWarningUrl}/${scanId}
  // and append query parameters (?url=...&score=...&verdict=...) so the frontend
  // can render instantly even if the database is in stub/standalone mode.
  const queryParams = new URLSearchParams();
  queryParams.set('url', encodeURIComponent(originalUrl));
  queryParams.set('score', String(score));
  queryParams.set('verdict', verdict);
  if (scanId) {
    queryParams.set('scan_id', scanId);
  }
  if (scanResult.category) {
    queryParams.set('category', scanResult.category);
  }

  // Check if targetUrl already has a path or query
  try {
    const parsed = new URL(targetUrl);
    // If the path does not already end with the scanId, append it
    if (scanId && !parsed.pathname.endsWith(`/${scanId}`)) {
      parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}/${encodeURIComponent(scanId)}`;
    }
    // Append parameters
    for (const [key, value] of queryParams.entries()) {
      parsed.searchParams.set(key, value);
    }
    return parsed.toString();
  } catch {
    const separator = targetUrl.includes('?') ? '&' : '?';
    return `${targetUrl}${scanId ? '/' + encodeURIComponent(scanId) : ''}${separator}${queryParams.toString()}`;
  }
}
