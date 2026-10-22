/* SENTINEL — client-side target validation.
   Mirrors backend/target_validation.py so users get immediate feedback;
   the backend always re-validates (client checks are a convenience, not
   a security boundary). */
(() => {
  'use strict';

  const SENTINEL = (window.SENTINEL = window.SENTINEL || {});

  /* Demo targets used to sync the URL input when a demo profile is chosen. */
  const DEMO_TARGETS = {
    'demo-mixed': 'https://training.example.test',
    'demo-good': 'https://hardened.example.test',
    'demo-poor': 'https://legacy.example.test',
  };

  /* Mirror of the backend port allowlist (backend/config.py). */
  const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);

  /**
   * Validate a target URL the same way the backend will.
   * @param {string} raw
   * @returns {{ok: boolean, url?: string, error?: string}}
   */
  function validateTarget(raw) {
    const value = String(raw || '').trim();
    if (!value) {
      return { ok: false, error: 'A target URL is required.' };
    }
    if (value.length > 2048) {
      return { ok: false, error: 'Target URL exceeds the 2048 character limit.' };
    }
    if (/\s/.test(value)) {
      return { ok: false, error: 'Target URL contains whitespace.' };
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      return { ok: false, error: 'Enter a full URL including the scheme, e.g. https://example.com' };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, error: 'Only http:// and https:// targets are supported.' };
    }
    if (!parsed.hostname) {
      return { ok: false, error: 'Target URL is missing a host name.' };
    }
    if (parsed.username || parsed.password) {
      return { ok: false, error: 'URLs containing embedded credentials are not accepted.' };
    }
    if (parsed.port && !ALLOWED_PORTS.has(Number(parsed.port))) {
      return {
        ok: false,
        error: 'Port ' + parsed.port + ' is not permitted. Allowed ports: 80, 443, 8080, 8443.',
      };
    }
    return { ok: true, url: parsed.href };
  }

  SENTINEL.validation = { validateTarget, DEMO_TARGETS, ALLOWED_PORTS };
})();
