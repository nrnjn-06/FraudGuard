/**
 * FraudGuard: Background Service Worker (Manifest V3)
 * Domain, SSL Intelligence & ML Text Classification Bridge
 * 
 * Responsibilities:
 * - Receives domain analysis requests from content scripts.
 * - Receives text classification requests from content scripts.
 * - Communicates with the local FastAPI backend (http://127.0.0.1:8001).
 * - Handles backend offline states gracefully without breaking extension functionality.
 * - Does NOT intercept tabs, cookies, or user browsing history.
 */

const BACKEND_HOSTS = ['http://127.0.0.1:8001', 'http://localhost:8001'];
const REQUEST_TIMEOUT_MS = 10000;

/**
 * Attempts to fetch from backend with 127.0.0.1 and localhost fallback.
 * Eliminates IPv6 loopback resolution mismatches when uvicorn binds to 127.0.0.1.
 */
async function fetchFromBackend(endpointPath, options = {}) {
  let lastError = null;

  for (const host of BACKEND_HOSTS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const url = `${host}${endpointPath}`;
      const fetchOptions = {
        ...options,
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          ...(options.headers || {})
        }
      };

      const response = await fetch(url, fetchOptions);
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      return await response.json();
    } catch (err) {
      clearTimeout(timeoutId);
      lastError = err;
      if (err.name === 'AbortError') {
        throw new Error('Backend request timed out');
      }
    }
  }

  throw lastError || new Error('Backend unreachable');
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || !request.action) {
    return false;
  }

  // Domain & SSL Intelligence
  if (request.action === 'analyzeDomain') {
    const domain = request.domain;
    if (!domain || typeof domain !== 'string') {
      sendResponse({ success: false, error: 'Invalid domain specified' });
      return false;
    }

    fetchFromBackend(`/analyze-domain?domain=${encodeURIComponent(domain)}`, { method: 'GET' })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));

    return true; // Asynchronous response
  }

  // ML Dark-Pattern Text Classification
  if (request.action === 'analyzeText') {
    const text = request.text;
    if (!text || typeof text !== 'string' || !text.trim()) {
      sendResponse({ success: false, error: 'Invalid or empty text specified' });
      return false;
    }

    fetchFromBackend('/analyze-text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text.trim() })
    })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));

    return true; // Asynchronous response
  }

  // FraudGuard Scoring Engine Bridge
  if (request.action === 'calculateScore') {
    const payload = request.payload || {};

    fetchFromBackend('/calculate-score', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));

    return true; // Asynchronous response
  }

  // FraudGuard Overall Risk Assessment Engine Bridge
  if (request.action === 'calculateRisk') {
    const payload = request.payload || {};

    fetchFromBackend('/calculate-risk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));

    return true; // Asynchronous response
  }

  return false;
});
