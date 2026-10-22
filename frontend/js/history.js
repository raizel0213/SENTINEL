/* SENTINEL — scan history.
   Primary store: the backend SQLite database. When the API is unreachable,
   browser-mode records fall back to localStorage so the workstation stays
   usable offline (matching SENTINEL 1.x behavior). */
(() => {
  'use strict';

  const SENTINEL = (window.SENTINEL = window.SENTINEL || {});
  const $ = (s) => document.querySelector(s);
  const OFFLINE_KEY = 'sentinelOfflineHistory';
  const MAX_OFFLINE = 30;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function prettyTime(value) {
    if (!value) return '—';
    const d = new Date(value);
    return isNaN(d) ? '—' : d.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  }

  /* --- offline store -------------------------------------------------------- */

  function readOffline() {
    try {
      const parsed = JSON.parse(localStorage.getItem(OFFLINE_KEY) || '[]');
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveOffline(record) {
    const entry = {
      id: null,
      timestamp: record.timestamp,
      target: record.target,
      mode: record.mode,
      modeLabel: record.modeLabel,
      score: record.score,
      total: record.checks.length,
      high: record.checks.filter((c) => ['High', 'Critical'].includes(c.severity)).length,
      snapshot: record,
    };
    const entries = [entry, ...readOffline().filter((e) => e.timestamp !== entry.timestamp)]
      .slice(0, MAX_OFFLINE);
    try { localStorage.setItem(OFFLINE_KEY, JSON.stringify(entries)); } catch { /* quota */ }
  }

  function clearOffline() {
    try { localStorage.removeItem(OFFLINE_KEY); } catch { /* ignore */ }
  }

  /* --- merged history --------------------------------------------------------- */

  function entries() {
    return SENTINEL.app.state.historyList || [];
  }

  async function load() {
    let items = [];
    if (SENTINEL.app.state.apiOnline) {
      try {
        const data = await SENTINEL.api.listScans();
        items = (data.items || []).map((s) => ({
          id: s.id,
          timestamp: s.timestamp,
          target: s.target,
          mode: s.mode,
          modeLabel: s.mode_label || s.mode,
          score: s.score,
          total: s.total,
          high: s.high,
        }));
      } catch { /* fall through to offline-only view */ }
    }
    const offline = readOffline();
    SENTINEL.app.state.historyList = [...offline, ...items].slice(0, 60);
    renderHistory();
    renderRecent();
    const tag = $('#historySourceTag');
    if (tag) {
      tag.textContent = SENTINEL.app.state.apiOnline
        ? (offline.length ? 'LOCAL API + ' + offline.length + ' OFFLINE' : 'LOCAL API DATABASE')
        : 'BROWSER LOCALSTORAGE (API OFFLINE)';
    }
  }

  function renderRecent() {
    const list = $('#recentList');
    list.replaceChildren();
    const records = entries().slice(0, 3);
    if (!records.length) {
      const li = el('li');
      li.append(el('div', 'left', 'No previous scans'));
      list.append(li);
      return;
    }
    records.forEach((r) => {
      const li = el('li');
      const left = el('div', 'left');
      left.append(
        el('div', 'title', r.target),
        el('div', 'meta', prettyTime(r.timestamp) + ' · ' + (r.modeLabel || r.mode).toUpperCase())
      );
      li.append(left, el('span', 'tag', (r.score_applicable === false || r.mode === 'browser') ? 'N/A · unscored' : (r.score ?? '—') + '/100'));
      list.append(li);
    });
  }

  function renderHistory() {
    const list = $('#historyList');
    list.replaceChildren();
    $('#historyEmpty').hidden = entries().length > 0;
    entries().forEach((r) => {
      const li = el('li');
      const left = el('div', 'left');
      left.append(
        el('div', 'title', r.target),
        el('div', 'meta', prettyTime(r.timestamp) + ' · ' + (r.modeLabel || r.mode).toUpperCase() +
          ' · ' + (r.total ?? '—') + ' checks')
      );
      const actions = el('div');
      actions.style.display = 'flex';
      actions.style.gap = '6px';
      actions.style.alignItems = 'center';
      actions.append(el('span', 'tag', (r.score_applicable === false || r.mode === 'browser') ? 'N/A · unscored' : (r.score ?? '—') + '/100'));
      if (!r.id) actions.append(el('span', 'tag demo', 'OFFLINE'));

      const open = el('button', 'quiet-btn small-btn', 'Load');
      open.type = 'button';
      open.addEventListener('click', () => loadEntry(r));

      li.append(left, actions);
      if (r.id) {
        const remove = el('button', 'quiet-btn small-btn', 'Delete');
        remove.type = 'button';
        remove.addEventListener('click', async () => {
          try {
            await SENTINEL.api.deleteScan(r.id);
            SENTINEL.app.toast('Record deleted.');
          } catch (error) {
            SENTINEL.app.toast(error.message);
          }
          load();
        });
        li.append(remove);
      }
      li.append(open);
      list.append(li);
    });
  }

  async function loadEntry(entry) {
    if (entry.id) {
      try {
        const record = await SENTINEL.api.getScan(entry.id);
        SENTINEL.app.setCurrent(SENTINEL.app.normalizeRecord(record));
        SENTINEL.app.navigate('overview');
        SENTINEL.app.toast('Saved scan loaded.');
        return;
      } catch (error) {
        SENTINEL.app.toast(error.message);
      }
    }
    if (entry.snapshot) {
      SENTINEL.app.setCurrent(SENTINEL.app.normalizeRecord(entry.snapshot));
      SENTINEL.app.navigate('overview');
      SENTINEL.app.toast('Saved scan loaded (offline record).');
    }
  }

  async function clearAll() {
    if (!confirm('Clear all SENTINEL scan history (local API database and offline browser records)?')) {
      return;
    }
    clearOffline();
    if (SENTINEL.app.state.apiOnline) {
      try {
        await SENTINEL.api.clearScans();
      } catch (error) {
        SENTINEL.app.toast(error.message);
      }
    }
    SENTINEL.app.state.historyList = [];
    renderHistory();
    renderRecent();
    SENTINEL.app.toast('Local scan history cleared.');
  }

  function bind() {
    $('#clearHistory').addEventListener('click', clearAll);
  }

  SENTINEL.history = { load, renderHistory, renderRecent, saveOffline, clearAll, bind, entries };
})();
