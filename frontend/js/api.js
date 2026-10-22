/* SENTINEL — API client.
   v2.5.0: the API is same-origin only. The UI is served by the local Flask
   backend (http://127.0.0.1:5050 by default); the previous file:// CORS
   fallback was removed together with the server-side wildcard CORS headers
   as a hardening measure. All failures normalize into ApiError. */
(() => {
  'use strict';

  const SENTINEL = (window.SENTINEL = window.SENTINEL || {});

  class ApiError extends Error {
    constructor(status, code, message) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.code = code;
    }
  }

  async function request(path, options = {}, timeoutMs = 20000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(path, {
        method: options.method || 'GET',
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        body: options.body,
        signal: controller.signal,
      });
      let data = null;
      try { data = await response.json(); } catch { /* non-JSON body */ }
      if (!response.ok) {
        const err = (data && data.error) || {};
        throw new ApiError(
          response.status,
          err.code || 'HTTP_' + response.status,
          err.message || ('Request failed (' + response.status + ').')
        );
      }
      return data;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      if (error && error.name === 'AbortError') {
        throw new ApiError(0, 'TIMEOUT', 'The request timed out.');
      }
      throw new ApiError(
        0,
        'NETWORK',
        'The local SENTINEL API is unreachable. Start it with: python -m backend.app, '
        + 'then open http://127.0.0.1:5050'
      );
    } finally {
      clearTimeout(timer);
    }
  }

  const api = {
    ApiError,
    getHealth: () => request('/api/health', {}, 4000),
    getChecks: () => request('/api/checks', {}, 6000),
    runScan: (payload) => request('/api/scan', { method: 'POST', body: JSON.stringify(payload) }, 90000),
    listScans: () => request('/api/scans', {}, 8000),
    getScan: (id) => request('/api/scans/' + encodeURIComponent(id), {}, 8000),
    deleteScan: (id) => request('/api/scans/' + encodeURIComponent(id), { method: 'DELETE' }, 8000),
    clearScans: () => request('/api/scans', { method: 'DELETE' }, 8000),
    reportUrl: (id, format) =>
      '/api/scans/' + encodeURIComponent(id) + '/report?format=' + encodeURIComponent(format),
  };

  SENTINEL.api = api;
})();
