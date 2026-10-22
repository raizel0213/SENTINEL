/* SENTINEL — findings register, filters, detail inspection and evidence
   completeness. Rendering uses createElement/textContent only (no innerHTML
   with data), matching the XSS-safe behavior of SENTINEL 1.x. */
(() => {
  'use strict';

  const SENTINEL = (window.SENTINEL = window.SENTINEL || {});
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];

  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4, Pass: 5 };

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function sevClass(severity) {
    return 'sev ' + String(severity || 'info').toLowerCase();
  }

  function current() { return SENTINEL.app ? SENTINEL.app.state.current : null; }

  /* --- register ---------------------------------------------------------- */

  function filteredChecks() {
    const record = current();
    if (!record) return [];
    const query = ($('#searchFindings').value || '').trim().toLowerCase();
    const sev = $('#severityFilter').value;
    const rows = record.checks.filter((c) => {
      const severityOk = sev === 'all' || String(c.severity).toLowerCase() === sev.toLowerCase();
      const haystack = [c.name, c.header, c.evidence, c.description, c.id]
        .join(' ').toLowerCase();
      return severityOk && haystack.includes(query);
    });
    if ($('#sortFindings').value === 'name') {
      rows.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    } else {
      rows.sort((a, b) =>
        (SEV_ORDER[a.severity] ?? 6) - (SEV_ORDER[b.severity] ?? 6));
    }
    return rows;
  }

  function makeRow(check, container) {
    const selectedId = SENTINEL.app.state.selectedId;
    const tr = document.createElement('tr');
    tr.dataset.id = check.id;
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-selected', check.id === selectedId ? 'true' : 'false');
    if (check.id === selectedId) tr.classList.add('selected');

    const td1 = el('td');
    td1.append(el('span', sevClass(check.severity), check.severity));

    const td2 = el('td');
    td2.append(
      el('div', 'finding-name', check.name),
      el('div', 'finding-meta', check.id + ' · ' + check.header + ' · ' + (check.outcome || 'informational'))
    );

    const td3 = el('td');
    td3.append(el('span', 'tag', check.status || 'Observed'));

    tr.append(td1, td2, td3);
    const select = () => {
      SENTINEL.app.state.selectedId = check.id;
      render();
      renderDetail();
    };
    tr.addEventListener('click', select);
    tr.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        select();
      }
    });
    container.append(tr);
  }

  function render() {
    const record = current();
    const rows = filteredChecks();
    for (const id of ['findingsBody', 'findingsBody2']) {
      const body = $('#' + id);
      body.replaceChildren();
      rows.forEach((c) => makeRow(c, body));
    }
    $('#findingsEmpty').hidden = rows.length > 0;
    $('#findingCountTag').textContent = rows.length + ' record' + (rows.length === 1 ? '' : 's');
    $('#findingCountTag2').textContent = rows.length + ' record' + (rows.length === 1 ? '' : 's');
    $('#navFindingCount').textContent = record && record.checks.length ? String(record.checks.length) : '';
  }

  /* --- detail panel -------------------------------------------------------- */

  function renderDetail() {
    const record = current();
    const body = $('#detailBody');
    body.replaceChildren();
    const check = record
      ? (record.checks.find((x) => x.id === SENTINEL.app.state.selectedId) || record.checks[0])
      : null;

    if (!check) {
      const empty = el('div', 'empty');
      empty.append(el('strong', null, 'No finding selected'));
      empty.append(document.createTextNode(
        record ? 'This record has no findings.' : 'Run an analysis to inspect findings here.'));
      body.append(empty);
      $('#detailRef').textContent = 'REF —';
      return;
    }

    $('#detailRef').textContent = check.id;
    body.append(el('div', 'detail-kicker', 'Selected observation / ' + check.id));
    body.append(el('h2', 'detail-title', check.name));

    const tags = el('div', 'detail-tags');
    tags.append(
      el('span', sevClass(check.severity), check.severity),
      el('span', 'tag', check.status || 'Observed')
    );
    body.append(tags);

    const sections = [
      ['Summary', check.description],
      ['Potential impact', check.impact],
      ['Observed evidence', check.evidence],
      ['Recommended remediation', check.fix],
    ];
    for (const [title, value] of sections) {
      const section = el('section', 'detail-section');
      section.append(el('h3', null, title));
      section.append(
        title === 'Observed evidence'
          ? el('div', 'evidence', value)
          : el('p', null, value)
      );
      body.append(section);
    }

    const actions = el('div', 'detail-actions');
    const copy = el('button', 'quiet-btn small-btn', 'Copy evidence');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(String(check.evidence || ''));
        SENTINEL.app.toast('Evidence copied.');
      } catch {
        SENTINEL.app.toast('Clipboard access unavailable in this context.');
      }
    });
    const docs = el('button', 'quiet-btn small-btn', 'Open documentation ↗');
    docs.type = 'button';
    docs.addEventListener('click', () => window.open(check.docs, '_blank', 'noopener,noreferrer'));
    actions.append(copy, docs);
    body.append(actions);
  }

  /* --- evidence completeness ------------------------------------------------- */

  function cookieNames(record) {
    return (record.limitations || []).length >= 0 ? 'Not reviewed (see limitations)' : '—';
  }

  function tlsLabel(tls) {
    if (!tls) return 'Not applicable (no TLS session)';
    if (tls.verified === false) return 'Verification FAILED';
    if (tls.days_left !== null && tls.days_left !== undefined) {
      return 'Verified · expires ' + tls.not_after + ' (' + tls.days_left + ' days)';
    }
    if (tls.cert_error) return 'Verified · metadata unavailable';
    return 'Verified';
  }

  function renderEvidence() {
    const list = $('#evidenceList');
    list.replaceChildren();
    const record = current();

    if (!record) {
      const li = el('li');
      const left = el('div', 'left');
      left.append(el('div', 'title', 'No scan loaded'));
      left.append(el('div', 'meta', 'Run an analysis to populate evidence completeness.'));
      li.append(left);
      list.append(li);
      $('#evidenceTag').textContent = '—';
      return;
    }

    let items;
    if (record.mode === 'demo') {
      items = [
        ['Target', record.target],
        ['Execution mode', 'Simulated profile'],
        ['HTTP status', 'Unavailable'],
        ['Header visibility', 'Simulated, not observed'],
        ['Uncompleted checks', 'Live checks not performed'],
      ];
    } else if (record.mode === 'browser') {
      items = [
        ['Target', record.target],
        ['Execution mode', 'Browser fetch attempt'],
        ['HTTP status', record.status === null || record.status === undefined ? 'Unavailable' : String(record.status)],
        ['Header visibility', 'Only headers exposed by the browser'],
        ['Uncompleted checks', record.status ? 'Cookie inspection restricted' : 'Response unavailable'],
      ];
    } else {
      items = [
        ['Target', record.target],
        ['Final URL', record.final_url || record.target],
        ['Execution mode', 'Server-side scan (local API)'],
        ['HTTP status', record.status === null || record.status === undefined ? 'Unavailable' : String(record.status)],
        ['Response headers observed', String(record.observed ?? 0)],
        ['TLS certificate', tlsLabel(record.tls)],
        ['Redirect hops', String((record.redirect_chain || []).length)],
      ];
    }

    const tag = record.mode === 'demo' ? 'SIMULATED'
      : record.mode === 'server' ? 'OBSERVED'
      : (record.status ? 'OBSERVED' : 'LIMITED');

    for (const [label, value] of items) {
      const li = el('li');
      const left = el('div', 'left');
      left.append(el('div', 'title', label), el('div', 'meta', value));
      li.append(left, el('span', 'tag', tag));
      list.append(li);
    }
    $('#evidenceTag').textContent = record.mode === 'demo' ? 'Demo record'
      : record.mode === 'server' ? 'Server evidence' : 'Browser evidence';
  }

  /* --- init ------------------------------------------------------------------- */

  function bind() {
    $('#searchFindings').addEventListener('input', render);
    $('#severityFilter').addEventListener('change', render);
    $('#sortFindings').addEventListener('change', render);
  }

  SENTINEL.findings = { render, renderDetail, renderEvidence, bind, filteredChecks, $, $$, el };
})();
