/* SENTINEL — scan execution UI.
   Three modes, one form:
     server  → POST /api/scan {mode:"server", target, authorization:true}
     demo-*  → POST /api/scan {mode:"demo", profile}   (canned record, backend;
               no request is made, so no authorization field is required)
     browser → fetch() from this page (CORS-bound), result stored via the
               backend or, when the API is offline, in localStorage.
   Real scans (server/browser) are disabled until the authorization
   checkbox is confirmed; the backend independently enforces the same rule.
   Browser-mode check texts are ported from SENTINEL 1.x liveRun(). */
(() => {
  'use strict';

  const SENTINEL = (window.SENTINEL = window.SENTINEL || {});
  const $ = (s) => document.querySelector(s);
  const nowISO = () => new Date().toISOString();

  const REAL_MODES = new Set(['server', 'browser']);

  const BROWSER_SPECS = [
    ['strict-transport-security', 'Strict-Transport-Security', 'Info', 'HSTS not observable in browser response',
      'Configure HSTS over HTTPS after verifying the domain and subdomains.',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'],
    ['content-security-policy', 'Content-Security-Policy', 'Info', 'CSP not observable in browser response',
      'Design and test a CSP that matches the application\u2019s resource requirements.',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
    ['x-content-type-options', 'X-Content-Type-Options', 'Info', 'MIME-sniffing header not observable in browser response',
      'Serve correct MIME types and consider X-Content-Type-Options: nosniff.',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
    ['x-frame-options', 'X-Frame-Options', 'Info', 'X-Frame-Options not observable in browser response',
      'Consider CSP frame-ancestors and/or X-Frame-Options where appropriate.',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'],
    ['referrer-policy', 'Referrer-Policy', 'Info', 'Referrer-Policy not observable in browser response',
      'Choose a Referrer-Policy appropriate to application privacy requirements.',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
    ['permissions-policy', 'Permissions-Policy', 'Info', 'Permissions-Policy not observable in browser response',
      'Define a Permissions-Policy based on browser features the application uses.',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Permissions_Policy'],
  ];

  const BROWSER_LIMITATIONS = [
    'Browser CORS can prevent response inspection.',
    'Set-Cookie and HttpOnly details are not available to ordinary page JavaScript.',
    'This is not a full vulnerability scan.',
    'Only headers the browser exposes to JavaScript can be checked.',
  ];

  function isRealMode(profile) {
    return REAL_MODES.has(profile);
  }

  function authorizationGiven() {
    const box = $('#authorizeScan');
    return Boolean(box && box.checked);
  }

  function currentMode() {
    return $('#profile').value;
  }

  /* Keep the submit button in sync: real modes require the confirmation. */
  function syncScanButton() {
    const button = $('#scanButton');
    if (!button) return;
    const realMode = isRealMode(currentMode());
    if (realMode && !authorizationGiven()) {
      button.disabled = true;
      button.title = 'Confirm the authorization checkbox to enable real scans.';
    } else if (!button.dataset.busy) {
      button.disabled = false;
      button.title = '';
    }
  }

  function setBusy(busy) {
    const button = $('#scanButton');
    button.dataset.busy = busy ? '1' : '';
    button.disabled = busy || (isRealMode(currentMode()) && !authorizationGiven());
    button.textContent = busy ? 'Requesting…' : 'Run analysis →';
    if (busy) $('#targetState').textContent = 'Attempting request';
    else syncScanButton();
  }

  async function finish(record, message) {
    SENTINEL.app.setCurrent(record);
    await SENTINEL.history.load();
    SENTINEL.app.toast(message);
  }

  /* --- demo profiles ----------------------------------------------------------- */

  async function runDemo(profile, options = {}) {
    if (!SENTINEL.app.state.apiOnline) {
      SENTINEL.app.toast('Demo profiles are served by the local API — start the backend to use them.');
      return null;
    }
    setBusy(true);
    try {
      const record = await SENTINEL.api.runScan({ mode: 'demo', profile, persist: options.persist !== false });
      await finish(SENTINEL.app.normalizeRecord(record),
        options.silent ? 'Demo profile loaded.' : 'Demo profile loaded. No live request was made.');
      return record;
    } catch (error) {
      SENTINEL.app.toast(error.message);
      $('#targetState').textContent = 'Request failed';
      return null;
    } finally {
      setBusy(false);
    }
  }

  /* --- server scan ----------------------------------------------------------------- */

  async function runServer(rawUrl) {
    const check = SENTINEL.validation.validateTarget(rawUrl);
    if (!check.ok) {
      SENTINEL.app.toast('Invalid URL: ' + check.error);
      return;
    }
    if (!authorizationGiven()) {
      SENTINEL.app.toast('Confirm the authorization checkbox before running a real scan.');
      return;
    }
    setBusy(true);
    try {
      const record = await SENTINEL.api.runScan({
        mode: 'server', target: check.url, authorization: true,
      });
      await finish(SENTINEL.app.normalizeRecord(record), 'Server-side scan complete.');
    } catch (error) {
      $('#targetState').textContent = 'Request failed';
      SENTINEL.app.toast(error.message);
    } finally {
      setBusy(false);
    }
  }

  /* --- browser-mode scan (ported from SENTINEL 1.x liveRun) --------------------------- */

  async function runBrowser(rawUrl) {
    let url;
    try {
      url = new URL(String(rawUrl || '').trim());
      if (!['http:', 'https:'].includes(url.protocol)) {
        throw new Error('Only HTTP and HTTPS URLs are supported.');
      }
      if (url.username || url.password) {
        throw new Error('URLs containing credentials are not accepted.');
      }
    } catch (error) {
      SENTINEL.app.toast('Invalid URL: ' + error.message);
      return;
    }
    if (location.protocol === 'https:' && url.protocol === 'http:') {
      SENTINEL.app.toast('Blocked: an HTTPS page cannot fetch an insecure HTTP target.');
      return;
    }
    if (!authorizationGiven()) {
      SENTINEL.app.toast('Confirm the authorization checkbox before running a real scan.');
      return;
    }

    setBusy(true);
    const start = performance.now();
    let status = null;
    let checks = [];
    try {
      const response = await fetch(url.href, {
        method: 'GET', mode: 'cors', credentials: 'omit', redirect: 'follow', cache: 'no-store',
      });
      status = response.status;
      const visible = new Map();
      response.headers.forEach((value, key) => visible.set(key.toLowerCase(), value));

      checks = [];
      let index = 0;
      for (const [key, header, sev, missing, fix, docs] of BROWSER_SPECS) {
        index += 1;
        const value = visible.get(key);
        checks.push({
          id: 'LIVE-' + String(index).padStart(3, '0'),
          severity: 'Info',
          name: value ? header + ' observed (policy not validated)' : missing,
          header,
          status: value ? 'Observed; value needs review' : 'Inconclusive / not exposed',
          evidence: value ? header + ': ' + value : 'Response header was not exposed to browser JavaScript.',
          description: value
            ? 'The browser exposed this response header. This observation does not validate the policy or prove the control is effective.'
            : 'The browser did not expose this header to JavaScript. CORS filtering means this is inconclusive, not evidence that the server omitted it.',
          impact: 'Browser-visible response data is incomplete for server-side configuration assessment; no severity or risk conclusion is made from this observation.',
          fix,
          docs,
        });
      }
      checks.push({
        id: 'LIVE-HTTPS',
        severity: 'Info',
        name: url.protocol === 'https:' ? 'HTTPS URL requested (TLS not audited)' : 'HTTP URL requested (transport unencrypted)',
        header: 'URL scheme',
        status: url.protocol === 'https:' ? 'Scheme observed' : 'Scheme observed; review required',
        evidence: 'Requested URL scheme: ' + url.protocol + ' HTTP status: ' + status,
        description: 'This check records the URL scheme used for the request, not a full TLS or certificate audit.',
        impact: url.protocol === 'https:'
          ? 'Certificate and TLS details were not independently audited.'
          : 'HTTP does not provide transport encryption for the request.',
        fix: 'Verify HTTPS configuration and certificate validity using an authorized TLS assessment.',
        docs: 'https://developer.mozilla.org/en-US/docs/Web/HTTPS',
      });

      const result = {
        target: url.href,
        mode: 'browser',
        mode_label: 'Live browser request',
        timestamp: nowISO(),
        duration_ms: Math.round(performance.now() - start),
        http_status: status,
        observed: visible.size,
        checks,
        limitations: BROWSER_LIMITATIONS.concat(['Browser-mode results are not scored because CORS-filtered header visibility cannot establish server-side absence or policy effectiveness.']),
        score_applicable: false, score: null, grade: null,
      };
      try {
        const record = await SENTINEL.api.runScan({ mode: 'browser', result, authorization: true });
        await finish(SENTINEL.app.normalizeRecord(record), 'Browser-visible response analyzed.');
      } catch (apiError) {
        const local = SENTINEL.app.normalizeRecord(SENTINEL.reports.attachLocalScore(result));
        SENTINEL.history.saveOffline(local);
        await finish(local, 'API offline — browser result stored locally.');
      }
    } catch (error) {
      const result = {
        target: url.href,
        mode: 'browser',
        mode_label: 'Live browser request',
        timestamp: nowISO(),
        duration_ms: Math.round(performance.now() - start),
        http_status: null,
        observed: 0,
        checks: [{
          id: 'LIVE-ERR',
          severity: 'Info',
          name: 'Response could not be inspected',
          header: 'Fetch / CORS',
          status: 'Blocked or unavailable',
          evidence: error.name + ': ' + error.message,
          description: 'The browser did not provide a readable HTTP response to this page.',
          impact: 'No conclusions about the target\u2019s security headers can be made from this failed request.',
          fix: 'Confirm the target is reachable, use an authorized test environment, or run a server-side '
             + 'scanner you control. Do not disable browser protections to force access.',
          docs: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
        }],
        limitations: BROWSER_LIMITATIONS.concat(['Browser-mode results are not scored because CORS-filtered header visibility cannot establish server-side absence or policy effectiveness.']),
        score_applicable: false, score: null, grade: null,
      };
      try {
        const record = await SENTINEL.api.runScan({ mode: 'browser', result, authorization: true });
        await finish(SENTINEL.app.normalizeRecord(record),
          'No readable response; no live findings were fabricated.');
      } catch {
        const local = SENTINEL.app.normalizeRecord(SENTINEL.reports.attachLocalScore(result));
        SENTINEL.history.saveOffline(local);
        await finish(local, 'No readable response — record kept locally.');
      }
    } finally {
      setBusy(false);
    }
  }

  /* --- form wiring ------------------------------------------------------------------ */

  async function submit(event) {
    event.preventDefault();
    const profile = $('#profile').value;
    const rawUrl = $('#targetUrl').value.trim();
    if (profile === 'server') return runServer(rawUrl);
    if (profile === 'browser') return runBrowser(rawUrl);
    return runDemo(profile);
  }

  function useMode(mode) {
    SENTINEL.app.navigate('overview');
    if (mode === 'demo') {
      $('#profile').value = 'demo-mixed';
    } else {
      $('#profile').value = mode;
    }
    syncScanButton();
    $('#targetUrl').focus();
    SENTINEL.app.toast('Mode selected: ' + $('#profile').selectedOptions[0].textContent.trim());
  }

  function bind() {
    $('#scanForm').addEventListener('submit', submit);
    $('#profile').addEventListener('change', () => {
      const value = $('#profile').value;
      const demoTargets = SENTINEL.validation.DEMO_TARGETS;
      if (demoTargets[value]) {
        $('#targetUrl').value = demoTargets[value];
      }
      syncScanButton();
    });
    const authorize = $('#authorizeScan');
    if (authorize) {
      authorize.addEventListener('change', syncScanButton);
    }
    syncScanButton();
    document.querySelectorAll('[data-use-mode]').forEach((button) => {
      button.addEventListener('click', () => useMode(button.dataset.useMode));
    });
  }

  SENTINEL.scannerUI = { submit, runDemo, runServer, runBrowser, useMode, bind };
})();
