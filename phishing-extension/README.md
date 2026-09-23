# PhishGuard AI - Chrome Manifest V3 Extension

Real-time browser security extension powered by **PhishGuard AI** machine-learning detection engine. Automatically analyzes URLs during browser navigation, blocks confirmed phishing or suspicious domains before they can steal credentials, and routes users to a dedicated risk analysis warning page.

---

## 🏗️ Architecture Overview

```
                      ┌──────────────────────────────────────┐
                      │          Google Chrome / Edge         │
                      │         (Manifest V3 Browser)        │
                      └──────────────────┬───────────────────┘
                                         │ Navigates to URL
                                         ▼
                      ┌──────────────────────────────────────┐
                      │      Background Service Worker       │
                      │       (service-worker.js - MV3)      │
                      └────┬─────────────┬──────────────┬────┘
                           │             │              │
             1. Allowlist / Loop?        │              │
                   ▼                     │              │
             [Bypass / Allow]            │              │
                                   2. Cache Hit?        │
                                         ▼              │
                                   [Instant Action]     │
                                                        │ 3. API POST /api/v1/scan
                                                        ▼
                                         ┌───────────────────────────┐
                                         │  PhishGuard FastAPI Backend│
                                         │     (Port 8000 / ML)      │
                                         └──────────────┬────────────┘
                                                        │
                         ┌──────────────────────────────┴──────────────────────────┐
                         │ Verdict & Score (e.g. PHISHING, 94/100, SHAP features)  │
                         ▼                                                         ▼
                  [SAFE Result]                                            [DANGEROUS Result]
                 Allow navigation                                      Intercept & Redirect Tab
                (Zero interruption)                                                ▼
                                                                ┌─────────────────────────────────────┐
                                                                │ PhishGuard React Risk-Score Page    │
                                                                │ http://localhost:5173/risk-score/ID │
                                                                │  - Dangerous Website Alert          │
                                                                │  - Forensic Reasons & Metrics       │
                                                                │  - "Go Back to Safety" Action       │
                                                                └─────────────────────────────────────┘
```

---

## 📁 Directory Structure

```
phishing-extension/
├── manifest.json              # Chrome Manifest V3 configuration
├── background/
│   └── service-worker.js      # Background navigation interceptor & coordinator
├── popup/
│   ├── popup.html             # Clean glassmorphic popup UI
│   ├── popup.css              # Cyber-defense dark styling
│   └── popup.js               # Live tab status, score gauge, and stats
├── options/
│   ├── options.html           # Full settings page
│   ├── options.css            # Settings styling & layout
│   └── options.js             # Configuration manager & live API tester
├── utils/
│   ├── api.js                 # Backend API client with response normalizer
│   ├── cache.js               # Multi-tier memory + chrome.storage cache
│   └── url-utils.js           # URL validation, normalization & anti-loop logic
├── blocked/
│   ├── warning.html           # Standalone extension fallback warning screen
│   ├── warning.css            # Threat alert styling
│   └── warning.js             # Threat bypass & history handler
├── icons/
│   ├── icon16.png             # 16x16 extension badge
│   ├── icon48.png             # 48x48 extension badge
│   └── icon128.png            # 128x128 Chrome Web Store badge
├── test-extension.mjs         # Automated 20-scenario test suite
└── package.json               # Node module manifest for unit tests
```

---

## 🚀 Quick Setup & Installation

### Step 1: Start PhishGuard AI Backend & Frontend

1. **Backend**:
   ```powershell
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```
   *Health endpoint: `http://localhost:8000/health`*

2. **Frontend Website**:
   ```powershell
   cd frontend
   npm run dev
   ```
   *Dashboard & Risk Score page: `http://localhost:5173`*

### Step 2: Load Extension in Chrome

1. Open **Google Chrome** (or Chromium / Brave / Edge).
2. In the URL bar, go to:
   ```
   chrome://extensions/
   ```
3. Enable **"Developer mode"** in the top-right corner.
4. Click **"Load unpacked"** in the top-left toolbar.
5. Browse and select the directory:
   ```
   ...\phishguard-ai-main\phishguard-ai-main\phishing-extension
   ```
6. The **PhishGuard AI** extension icon will now appear in your browser toolbar! Pin it for quick access.

---

## ⚙️ Configuration & Endpoints Guide

Click the extension icon and select **Settings**, or right-click the extension icon and choose **Options**.

| Setting Field | Default Value | Description |
| :--- | :--- | :--- |
| **Phishing Detection API URL** | `http://localhost:8000/api/v1/scan` | Where URLs are POSTed. Also supports `/api/check-url`. |
| **Website Risk-Score URL** | `http://localhost:5173/risk-score` | Destination page when threats are intercepted. |
| **Fail-Safe Behavior** | `Warn & Allow Decision` | Action if backend is offline (`warn`, `allow`, or `block`). |
| **Cache Lifetime (Seconds)** | `1800` (30 minutes) | Prevents redundant scans of the same URL. |
| **Inspect Localhost** | `OFF` (Disabled) | Excludes `localhost` / `127.0.0.1` so development is uninterrupted. |
| **Allowed Domains** | `google.com`, `github.com`, etc. | Domains that completely bypass scanning. |
| **Blocked Domains** | Empty | Custom list of domains always blocked immediately. |

### Where to Configure Custom Keys / Authentication:
If your backend requires an API key in production, open [utils/api.js](file:///C:/Users/Ajay%20Ramesh/Downloads/SKCET/Mini%20Project/phishguard-ai-main/phishguard-ai-main/phishing-extension/utils/api.js):
```javascript
// Add Authorization header if required:
headers: {
  'Content-Type': 'application/json',
  'X-API-Key': options.apiKey || 'YOUR_PRODUCTION_API_KEY'
}
```

---

## 🛡️ Key Features & Safeguards

### 1. Loop Prevention
The extension checks `isOwnApplicationUrl` on every navigation. URLs belonging to:
- `http://localhost:8000` (Backend API)
- `http://localhost:5173` (Frontend Web App & Risk Score Page)
- Browser internal protocols (`chrome://`, `edge://`, `about:`, `file://`)
are **strictly exempted** from scanning to prevent recursive redirect loops.

### 2. High-Performance Caching
- **In-Memory + `chrome.storage.local` tier**: Known safe URLs resolve in `< 1ms` on repeat visits.
- Normalized URLs strip hashes/fragments to prevent cache fragmentation (`https://example.com/#top` shares cache with `https://example.com/`).
- Auto-pruned every 15 minutes via Chrome alarms.

### 3. Dedicated Risk-Score Page Integration
When a phishing site is detected:
1. Extension intercepts navigation before the malicious website can run scripts or render forms.
2. Redirects to `http://localhost:5173/risk-score/<scan_id>?url=...&score=...&verdict=PHISHING`.
3. The React web application retrieves forensic evidence (SHAP signals, brand impersonation, zero-day indicators) and displays:
   - 🚨 **Red Deceptive Website Interception Banner**
   - **Risk Score** (e.g. 94 / 100)
   - **Reasons** (Domain imitation, zero-day age, keyword signals)
   - **"Go Back to Safety"** button
   - **"Continue Anyway"** with security warning confirmation

### 4. Extension Built-in Fallback Warning
If the frontend Vite development server is offline, the extension includes a built-in fallback warning page at `blocked/warning.html` so users are never left unprotected.

---

## 🧪 Verification & Automated Testing

A dedicated test suite validating all 20 required scenarios is included:

```powershell
cd phishing-extension
node test-extension.mjs
```

### Scenarios Verified:
1. ✅ Safe URL (allowed without redirect)
2. ✅ Phishing URL (classified HIGH risk, flagged for redirect)
3. ✅ Suspicious URL (classified MEDIUM risk, flagged for redirect)
4. ✅ HTTP URL validation
5. ✅ HTTPS URL validation
6. ✅ URL with query parameters (properly preserved)
7. ✅ URL with fragments (canonical hash stripping)
8. ✅ URL containing encoded characters
9. ✅ Redirect chain handling
10. ✅ New tab (`chrome://newtab` excluded)
11. ✅ New window (`about:blank` excluded)
12. ✅ Multiple concurrent tabs isolation
13. ✅ Backend API timeout handling
14. ✅ Backend API unavailable fail-safe
15. ✅ Invalid / malformed API response handling
16. ✅ Extension disabled mode
17. ✅ Risk-score page redirect formatting
18. ✅ Extension's own API & website domain recognition
19. ✅ Repeated visit cache hit consistency
20. ✅ Redirect-loop prevention
