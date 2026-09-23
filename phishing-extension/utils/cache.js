/**
 * PhishGuard Cache Manager
 * Provides a high-speed two-tier cache (In-Memory + chrome.storage.local)
 * to avoid duplicate API calls and ensure ultra-low latency navigation.
 */

import { normalizeUrl } from './url-utils.js';

const STORAGE_CACHE_KEY = 'phishguard_scan_cache';
const DEFAULT_TTL_SECONDS = 1800; // 30 minutes default

class ScanCache {
  constructor() {
    this.memoryCache = new Map();
    this.isHydrated = false;
    this.hydratePromise = this.hydrate();
  }

  /**
   * Load stored cache from chrome.storage.local into memory on worker startup
   */
  async hydrate() {
    if (this.isHydrated) return;
    try {
      if (typeof chrome !== 'undefined' && chrome.storage?.local) {
        const data = await chrome.storage.local.get(STORAGE_CACHE_KEY);
        const stored = data[STORAGE_CACHE_KEY];
        if (stored && typeof stored === 'object') {
          const now = Date.now();
          for (const [key, entry] of Object.entries(stored)) {
            if (entry && entry.expiresAt > now) {
              this.memoryCache.set(key, entry);
            }
          }
        }
      }
    } catch (e) {
      console.warn('[PhishGuard Cache] Hydration error:', e);
    } finally {
      this.isHydrated = true;
    }
  }

  /**
   * Look up a URL in cache
   * @param {string} url
   * @returns {Promise<Object|null>}
   */
  async get(url) {
    await this.hydratePromise;
    const key = normalizeUrl(url);
    const entry = this.memoryCache.get(key);

    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.memoryCache.delete(key);
      this.persist();
      return null;
    }

    return entry.data;
  }

  /**
   * Store a scan result in cache
   * @param {string} url
   * @param {Object} data - normalized scan response
   * @param {number} [ttlSeconds]
   */
  async set(url, data, ttlSeconds = DEFAULT_TTL_SECONDS) {
    await this.hydratePromise;
    const key = normalizeUrl(url);
    const now = Date.now();
    const expiresAt = now + (ttlSeconds > 0 ? ttlSeconds : DEFAULT_TTL_SECONDS) * 1000;

    const entry = {
      key,
      data,
      cachedAt: now,
      expiresAt,
    };

    this.memoryCache.set(key, entry);

    // Limit memory size (max 1000 entries)
    if (this.memoryCache.size > 1000) {
      const oldestKey = this.memoryCache.keys().next().value;
      this.memoryCache.delete(oldestKey);
    }

    await this.persist();
  }

  /**
   * Persist in-memory cache to chrome.storage.local
   */
  async persist() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage?.local) {
        const obj = {};
        for (const [k, v] of this.memoryCache.entries()) {
          obj[k] = v;
        }
        await chrome.storage.local.set({ [STORAGE_CACHE_KEY]: obj });
      }
    } catch (e) {
      console.warn('[PhishGuard Cache] Persist error:', e);
    }
  }

  /**
   * Clear all cached results
   */
  async clear() {
    this.memoryCache.clear();
    try {
      if (typeof chrome !== 'undefined' && chrome.storage?.local) {
        await chrome.storage.local.remove(STORAGE_CACHE_KEY);
      }
    } catch (e) {
      console.warn('[PhishGuard Cache] Clear error:', e);
    }
  }

  /**
   * Remove expired entries
   */
  async prune() {
    await this.hydratePromise;
    const now = Date.now();
    let changed = false;

    for (const [key, entry] of this.memoryCache.entries()) {
      if (!entry || entry.expiresAt <= now) {
        this.memoryCache.delete(key);
        changed = true;
      }
    }

    if (changed) {
      await this.persist();
    }
  }

  /**
   * Total number of cached items
   */
  size() {
    return this.memoryCache.size;
  }
}

export const scanCache = new ScanCache();
