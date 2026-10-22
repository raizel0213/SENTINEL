/* SENTINEL — application core.
   Central state, navigation, theme, toasts, record normalization and the
   boot sequence (health probe → registry → initial record → history). */
(() => {
  'use strict';

  const SENTINEL = (window.SENTINEL = window.SENTINEL || {});
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const nowISO = () => new Date().toISOString();

  function prettyTime(value) {
    if (!value) return '—';
    const d = new Date(value);
    return isNaN(d) ? '—' : d.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  const PAGE_TITLES = {
    overview: 'Overview',
    newscan: 'New scan',
    findings: 'Findings',
    history: 'Scan history',
    reports: 'Reports',
    methodology: 'Methodology',
  };

  const state = {
    current: null,        // normalized scan record
    selectedId: null,     // selected finding id
    apiOnline: false,     // backend reachability
    checksMeta: [],       // registry metadata from /api/checks
    historyList: [],      // merged history summaries
  };

  /* --- toast ------------------------------------------------------------------ */

  function toast(message) {
    const elNode = $('#toast');
    elNode.textContent = message;
    elNode.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { elNode.hidden = true; }, 3200);
  }

  /* --- record normalization ------------------------------------------------------ */

  /**
   * Accept records from the API (snake_case) or local fallbacks (camelCase)
   * and produce the internal shape used by every renderer.
   */
  function normalizeRecord(input) {
    if (!input || typeof input !== 'object') return null;
    const record = { ...input };
    record.status = record.http_status !== undefined && record.http_status !== null
      ? record.http_status
      : (record.status ?? null);
    record.duration = record.duration_ms !== undefined && record.duration_ms !== null
      ? record.duration_ms
      : (record.duration ?? null);
    record.modeLabel = record.mode_label || record.modeLabel
      || (record.mode === 'demo' ? 'Demo profile'
        : record.mode === 'server' ? 'Server-side scan' : 'Live browser request');
    record.checks = Array.isArray(record.checks) ? record.checks : [];
    record.limitations = Array.isArray(record.limitations) ? record.limitations : [];
    record.redirect_chain = Array.isArray(record.redirect_chain) ? record.redirect_chain : [];
    record.grade = record.grade || null;
    record.counts = record.counts || null;
    record.timestamp = record.timestamp || nowISO();
    return record;
  }

  /** Replace the current record and re-render the whole workstation. */
  function setCurrent(record) {
    state.current = record;
    state.selectedId = record && record.checks.length ? record.checks[0].id : null;
    renderAll();
  }

  /* --- navigation & theme ----------------------------------------------------------- */

  function navigate(page) {
    $$('.section-page').forEach((s) => s.classList.toggle('active', s.id === 'page-' + page));
    $$('.nav button').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
    $('#crumbPage').textContent = PAGE_TITLES[page] || 'Overview';
    if (page === 'findings') SENTINEL.findings.render();
    if (page === 'history') SENTINEL.history.load();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function applyTheme(dark) {
    if (dark) document.documentElement.dataset.theme = 'dark';
    else delete document.documentElement.dataset.theme;
    try { localStorage.setItem('sentinelTheme', dark ? 'dark' : 'light'); } catch { /* ignore */ }
  }

  function bindTheme() {
    try {
      if (localStorage.getItem('sentinelTheme') === 'dark') applyTheme(true);
    } catch { /* ignore */ }
    $('#themeToggle').addEventListener('click', () => {
      applyTheme(document.documentElement.dataset.theme !== 'dark');
    });
  }

  /* --- rendering ----------------------------------------------------------------------- */

  function modeTagFor(record) {
    if (!state.apiOnline && !record) return ['OFFLINE', 'tag demo'];
    if (!record) return ['READY', 'tag'];
    if (record.mode === 'demo') return ['DEMO MODE', 'tag demo'];
    if (record.mode === 'browser') return ['LIVE ATTEMPT', 'tag live'];
    return ['SERVER SCAN', 'tag live'];
  }

  function renderNotice() {
    const record = state.current;
    const notice = $('#notice');
    notice.replaceChildren();
    const mark = document.createElement('span');
    const copy = document.createElement('div');

    if (!record) {
      mark.className = 'mark';
      mark.textContent = '!';
      if (state.apiOnline) {
        copy.append(el('strong', null, 'NO RECORD LOADED. '),
          document.createTextNode('Run an analysis to populate the workstation.'));
      } else {
        copy.append(el('strong', null, 'BACKEND OFFLINE. '),
          document.createTextNode('Start the local API with \u201Cpython -m backend.app\u201D (or ./run.sh) '
            + 'and reload. Browser-mode scans and local exports remain available.'));
      }
    } else if (record.mode === 'demo') {
      mark.className = 'mark';
      mark.textContent = '!';
      copy.append(el('strong', null, 'DEMO DATA — NOT A LIVE SCAN. '),
        document.createTextNode('These findings are illustrative examples. '
          + 'No request was made to the displayed target.'));
    } else if (record.mode === 'browser' && !record.status) {
      mark.className = 'mark';
      mark.textContent = '!';
      copy.append(el('strong', null, 'LIVE REQUEST COULD NOT BE VERIFIED. '),
        document.createTextNode('The browser did not expose a readable response. This may be caused by CORS, '
          + 'TLS, network, or mixed-content restrictions; no headers were inferred.'));
    } else if (record.mode === 'browser') {
      mark.className = 'mark';
      mark.textContent = 'i';
      copy.append(el('strong', null, 'LIVE BROWSER RESPONSE. '),
        document.createTextNode('HTTP ' + record.status + ' was received. Browser-visible headers are a CORS-filtered subset; '
          + 'missing headers are inconclusive and this mode is not scored.'));
    } else {
      mark.className = 'mark';
      mark.textContent = 'i';
      copy.append(el('strong', null, 'SERVER-SIDE SCAN COMPLETE. '),
        document.createTextNode('HTTP ' + record.status + ' was captured directly from the target response '
          + 'by the local scanner process. This is a passive configuration review — it does not prove or '
          + 'disprove exploitability.'));
    }
    notice.append(mark, copy);
  }

  function renderAll() {
    const record = state.current;
    const counts = record && record.counts ? record.counts : null;
    const high = record
      ? record.checks.filter((c) => ['High', 'Critical'].includes(c.severity)).length
      : 0;

    const [modeText, modeClass] = modeTagFor(record);
    const modeTag = $('#modeTag');
    modeTag.textContent = modeText;
    modeTag.className = modeClass;

    if (record) {
      $('#scoreRing').textContent = record.mode === 'browser' ? 'N/A' : (record.score ?? '—');
      $('#scoreText').textContent = record.mode === 'browser' ? 'Not scored' : (record.score ?? '—') + ' / 100';
      $('#scoreSub').textContent = record.mode === 'demo' ? 'Simulated score'
        : record.mode === 'browser' ? 'Not scored · browser visibility is incomplete'
        : 'Grade ' + (record.grade || '—') + ' · educational heuristic';
      $('#totalCount').textContent = counts && Number.isFinite(counts.findings)
        ? counts.findings
        : record.checks.filter((c) => ['Critical', 'High', 'Medium', 'Low'].includes(c.severity)).length;
      const assessment = record.assessment || {};
      $('#findingsSub').textContent = record.mode === 'browser'
        ? 'Coverage N/A · CORS-limited observations'
        : `${assessment.coverage_percent ?? '—'}% check coverage · score is an educational heuristic`;
      $('#highCount').textContent = high;
      $('#observedCount').textContent = record.observed ?? record.checks.length;
      $('#observedSub').textContent = record.mode === 'demo' ? 'Simulated checks'
        : record.mode === 'browser' ? 'Browser-visible observations only'
        : 'Executed server-side checks';
      $('#lastScan').textContent = prettyTime(record.timestamp);
      $('#durationLabel').textContent = (record.duration === null || record.duration === undefined)
        ? 'Duration not measured'
        : record.duration + ' ms measured';
      $('#targetState').textContent = record.mode === 'demo' ? 'Demo profile loaded'
        : record.mode === 'browser' && !record.status ? 'Request blocked / unavailable'
        : 'Response received';
    } else {
      $('#scoreRing').textContent = '—';
      $('#scoreText').textContent = '— / 100';
      $('#scoreSub').textContent = state.apiOnline ? 'Awaiting analysis' : 'Backend offline';
      $('#totalCount').textContent = '0';
      $('#findingsSub').textContent = 'Checks that indicate a potential weakness';
      $('#highCount').textContent = '0';
      $('#observedCount').textContent = '0';
      $('#observedSub').textContent = '—';
      $('#lastScan').textContent = '—';
      $('#durationLabel').textContent = 'Duration not measured';
      $('#targetState').textContent = 'Ready for analysis';
    }

    renderNotice();
    SENTINEL.findings.render();
    SENTINEL.findings.renderDetail();
    SENTINEL.findings.renderEvidence();
    SENTINEL.history.renderRecent();
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* --- methodology registry ------------------------------------------------------------------ */

  function renderRegistry() {
    const body = $('#registryBody');
    body.replaceChildren();
    const rows = state.checksMeta;
    $('#registryCount').textContent = rows.length ? rows.length + ' checks registered' : '—';
    $('#registryEmpty').hidden = rows.length > 0;
    rows.forEach((check) => {
      const tr = document.createElement('tr');
      tr.style.cursor = 'default';
      const td1 = el('td', 'mono', check.id);
      td1.style.fontSize = '10px';
      const td2 = el('td');
      td2.append(
        el('div', 'finding-name', check.name),
        el('div', 'finding-meta', check.description)
      );
      tr.append(td1, td2, el('td', 'mono', check.category), el('td'));
      tr.children[3].append(el('span', 'tag', check.category === 'transport' ? 'Transport'
        : check.category === 'cookies' ? 'Cookies' : 'Headers'));
      body.append(tr);
    });
  }

  /* --- boot sequence ---------------------------------------------------------------------------- */

  async function boot() {
    bindTheme();
    $$('.nav button').forEach((b) => b.addEventListener('click', () => navigate(b.dataset.page)));
    $$('[data-goto]').forEach((b) => b.addEventListener('click', () => navigate(b.dataset.goto)));
    SENTINEL.findings.bind();
    SENTINEL.history.bind();
    SENTINEL.reports.bind();
    SENTINEL.scannerUI.bind();

    // 1) probe the local API
    try {
      const health = await SENTINEL.api.getHealth();
      state.apiOnline = true;
      $('#sideMode').textContent = 'API online · v' + (health.version || '?');
      $('#statusDot').className = 'dot';
    } catch {
      state.apiOnline = false;
      $('#sideMode').textContent = 'Backend offline';
      $('#statusDot').className = 'dot offline';
    }

    // 2) check registry for the methodology page
    if (state.apiOnline) {
      try {
        const data = await SENTINEL.api.getChecks();
        state.checksMeta = data.checks || [];
      } catch { state.checksMeta = []; }
      renderRegistry();
    } else {
      renderRegistry();
    }

    // 3) initial record: most recent history entry, else a non-persisted demo
    if (state.apiOnline) {
      try {
        const data = await SENTINEL.api.listScans();
        if (data.items && data.items.length) {
          const record = await SENTINEL.api.getScan(data.items[0].id);
          setCurrent(normalizeRecord(record));
          toast('Loaded most recent scan record.');
        } else {
          const record = await SENTINEL.api.runScan({ mode: 'demo', profile: 'demo-mixed', persist: false });
          setCurrent(normalizeRecord(record));
          toast('Demo profile loaded. No live request was made.');
        }
      } catch {
        setCurrent(null);
        toast('The local API responded but a record could not be loaded.');
      }
    } else {
      setCurrent(null);
    }

    // 4) history (merged backend + offline)
    await SENTINEL.history.load();
    renderAll();
  }

  SENTINEL.app = {
    state,
    toast,
    navigate,
    setCurrent,
    normalizeRecord,
    renderAll,
    renderRegistry,
    boot,
    $,
    $$,
    el,
    prettyTime,
    nowISO,
  };

  document.addEventListener('DOMContentLoaded', boot);
})();
