/**
 * API Client for PhishGuard AI Backend
 * Communicates with the phishing detection backend and normalizes responses.
 */

import { extractDomain } from './url-utils.js';

export const DEFAULT_API_URL = 'http://localhost:8000/api/v1/scan';
export const DEFAULT_TIMEOUT_MS = 6000;

/**
 * Normalizes backend response from either PhishGuard AI format or generic format
 * into a standardized structure.
 * @param {Object} rawData
 * @param {string} originalUrl
 * @returns {Object}
 */
export function normalizeScanResponse(rawData, originalUrl) {
  if (!rawData || typeof rawData !== 'object') {
    throw new Error('Invalid backend response: empty or non-object');
  }

  // 1. Determine Verdict & Score
  let score = 0;
  if (typeof rawData.score === 'number') {
    score = rawData.score;
  } else if (typeof rawData.riskScore === 'number') {
    score = rawData.riskScore;
  }

  let verdict = 'SAFE';
  if (rawData.verdict) {
    verdict = String(rawData.verdict).toUpperCase();
  } else if (rawData.isPhishing || rawData.riskLevel === 'HIGH' || score >= 70) {
    verdict = 'PHISHING';
  } else if (rawData.isSuspicious || rawData.riskLevel === 'MEDIUM' || score >= 40) {
    verdict = 'SUSPICIOUS';
  }

  const isPhishing = verdict === 'PHISHING' || rawData.isPhishing === true;
  const isSuspicious = verdict === 'SUSPICIOUS' || rawData.isSuspicious === true;
  const isDangerous = isPhishing || isSuspicious || score >= 40;

  // 2. Risk Level String
  let riskLevel = 'LOW';
  if (isPhishing || score >= 70) {
    riskLevel = 'HIGH';
  } else if (isSuspicious || score >= 40) {
    riskLevel = 'MEDIUM';
  }

  // 3. Scan ID
  const scanId = rawData.scan_id || rawData.scanId || rawData.id || '';

  // 4. Domain & Category
  const domain = rawData.domain || extractDomain(originalUrl);
  const category = rawData.category || 'generic';

  // 5. Reasons extraction (from SHAP explainability or raw reasons)
  const reasons = [];

  // If raw reasons array provided
  if (Array.isArray(rawData.reasons) && rawData.reasons.length > 0) {
    reasons.push(...rawData.reasons);
  }

  // Extract from PhishGuard SHAP features if available
  if (Array.isArray(rawData.shap)) {
    const phishingShap = rawData.shap.filter(
      (s) => s.direction === 'phishing' || s.shap_value > 0
    );
    for (const item of phishingShap.slice(0, 4)) {
      if (item.label) {
        reasons.push(item.label);
      } else if (item.feature) {
        reasons.push(formatFeatureName(item.feature));
      }
    }
  }

  // Additional context clues if reasons are sparse
  if (reasons.length === 0) {
    if (rawData.closest_brand && rawData.visual_similarity > 0.6) {
      reasons.push(`Suspicious visual imitation of ${rawData.closest_brand}`);
    }
    if (rawData.is_zero_day) {
      reasons.push('Zero-day domain detected (fresh registration with no reputation)');
    }
    if (typeof rawData.domain_age_days === 'number' && rawData.domain_age_days < 14) {
      reasons.push(`Domain registered very recently (${rawData.domain_age_days} days ago)`);
    }
    if (isDangerous && reasons.length === 0) {
      reasons.push('Heuristic and machine-learning risk indicators flagged this URL');
    }
  }

  return {
    success: true,
    url: rawData.url || originalUrl,
    domain,
    score,
    verdict,
    riskLevel,
    isPhishing,
    isSuspicious,
    isDangerous,
    confidence: typeof rawData.confidence === 'number' ? rawData.confidence : (score / 100),
    scan_id: scanId,
    scanId,
    category,
    reasons,
    domainAgeDays: rawData.domain_age_days,
    registrar: rawData.registrar,
    sslIssuer: rawData.ssl_issuer,
    closestBrand: rawData.closest_brand,
    visualSimilarity: rawData.visual_similarity,
    raw: rawData,
  };
}

/**
 * Turns feature_name into human-readable label
 * @param {string} feat
 * @returns {string}
 */
function formatFeatureName(feat) {
  return feat
    .replace(/^has_/, '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Calls the phishing detection API
 * @param {string} urlToScan
 * @param {Object} options
 * @param {string} [options.apiUrl]
 * @param {number} [options.timeoutMs]
 * @returns {Promise<Object>}
 */
export async function checkUrlWithBackend(urlToScan, options = {}) {
  const apiUrl = options.apiUrl || DEFAULT_API_URL;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ url: urlToScan }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      return {
        success: false,
        error: 'API_ERROR',
        status: response.status,
        message: `Backend returned status ${response.status}: ${errorText}`,
      };
    }

    const json = await response.json();
    return normalizeScanResponse(json, urlToScan);
  } catch (err) {
    clearTimeout(timer);
    const isTimeout = err.name === 'AbortError';
    return {
      success: false,
      error: isTimeout ? 'API_TIMEOUT' : 'API_UNAVAILABLE',
      message: isTimeout
        ? `Backend request timed out after ${timeoutMs}ms`
        : `Could not connect to PhishGuard API at ${apiUrl}: ${err.message}`,
    };
  }
}
