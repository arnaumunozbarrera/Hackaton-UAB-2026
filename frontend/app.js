// Sentinel analyst UI on real data from the workflow database (src/webapp, /api/*).
// Every value is rendered as text (el() + text nodes): alert fields, logs and model output are attacker-influenced.
'use strict';

const QUEUE_PAGE_SIZE = 6;
const REFRESH_MS = 10000;
const ANALYST_KEY = 'tarvia.analyst';
const REVIEW = ['awaiting_analyst', 'auto_closed'];
const WORKING = ['new', 'pending_llm', 'in_llm', 'llm_error'];
const STATUS_LABEL = {
  new: 'New', pending_llm: 'Kept, LLM pending', in_llm: 'In LLM', llm_error: 'LLM error',
  auto_closed: 'Auto-closed (to confirm)', awaiting_analyst: 'Awaiting analyst', accepted: 'Accepted', rejected: 'Rejected',
};
const VERDICTS = ['true_positive', 'benign_true_positive', 'false_positive'];
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

const state = {
  page: 'ops', alerts: [], stats: null, decisions: [], config: {}, filter: '', status: 'review', queuePage: 1,
  open: null, detail: null, tab: 'alert', toast: null, error: null, updated: null,
  analyst: localStorage.getItem(ANALYST_KEY) || '',
};
const root = document.querySelector('#app');

// ------------------------------------------------------------------ DOM helper (no innerHTML anywhere)
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key === 'value') node.value = value;
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const fmtTime = (ts) => (ts ? String(ts).replace('T', ' ').slice(0, 16) + ' UTC' : '—');
const pretty = (value) => el('pre', { class: 'json', text: JSON.stringify(value, null, 2) });
const sevTag = (s) => el('span', { class: `tag ${s || ''}`, text: s || '—' });
const origin = (o) => el('span', { class: 'who ai', text: o === 'auto_check' ? 'AI · basic checks' : 'AI · LLM' });
const human = (name) => el('span', { class: 'who human', text: `Human · ${name}` });

// ------------------------------------------------------------------ API
async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail ? (typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)) : response.statusText);
  return body;
}

async function refresh() {
  try {
    const [alerts, stats, decisions] = await Promise.all([api('/api/alerts'), api('/api/stats'), api('/api/decisions')]);
    Object.assign(state, { alerts, stats, decisions, error: null, updated: new Date() });
    if (state.open) state.detail = await api(`/api/alerts/${encodeURIComponent(state.open)}`);
  } catch (err) {
    state.error = `Cannot reach the triage API: ${err.message}`;
  }
  render();
}

async function openAlert(alertId) {
  state.open = alertId;
  state.tab = 'alert';
  state.detail = null;
  render();
  try {
    state.detail = await api(`/api/alerts/${encodeURIComponent(alertId)}`);
  } catch (err) {
    toast(err.message);
  }
  render();
}

async function sendDecision(body) {
  if (!state.analyst.trim()) return toast('Write your analyst name first (left sidebar).');
  try {
    const result = await api(`/api/alerts/${encodeURIComponent(state.open)}/decisions`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst: state.analyst.trim(), ...body }),
    });
    const ex = result.execution;
    toast(ex ? (ex.status ? `${ex.action} on ${ex.target}: ${ex.status}${ex.result && ex.result.detail ? ' — ' + ex.result.detail : ''}` : ex.reason)
      : result.alert_history ? `Verdict stored: ${result.alert_history}` : `Decision stored (${result.decision})`);
  } catch (err) {
    toast(`Not stored: ${err.message}`);
  }
  await refresh();
}

function toast(message) {
  state.toast = message;
render();
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { state.toast = null; render(); }, 6000);
}

// ------------------------------------------------------------------ shell
function shell(content) {
  const nav = (page, icon, label) => el('button', { class: state.page === page ? 'active' : '', onclick: () => { state.page = page; render(); } },
    el('span', { class: 'nav-icon', text: icon }), el('span', { text: label }));
  const analyst = el('input', {
    class: 'analyst-input', placeholder: 'Analyst name', value: state.analyst, 'aria-label': 'Analyst name',
    onchange: (e) => { state.analyst = e.target.value.trim(); localStorage.setItem(ANALYST_KEY, state.analyst); render(); },
  });
  const pending = state.alerts.filter((a) => REVIEW.includes(a.status)).length;
  return el('div', { class: 'app' },
    el('aside', { class: 'sidebar' },
      el('div', { class: 'brand' }, el('span', { class: 'mark', text: 'S' }), el('span', { text: 'sentinel' })),
      el('div', { class: 'nav-label', text: 'Workspace' }),
      el('nav', { class: 'nav' }, nav('ops', '◈', 'Operations center'), nav('history', '≡', 'Decision history')),
      el('div', { class: 'side-bottom' },
        el('small', {}, el('span', { class: 'status-dot' }), state.error ? 'Triage API unreachable' : 'Triage API connected'),
        el('div', { class: 'profile' }, el('span', { class: 'avatar', text: (state.analyst || '?').slice(0, 2).toUpperCase() }), analyst))),
    el('main', { class: 'main' },
      el('header', { class: 'topbar' },
        el('div', {}, el('div', { class: 'eyebrow', text: `TARVIA SOC / ${state.page === 'ops' ? 'OPERATIONS' : 'AUDIT LEDGER'}` }),
          el('h1', { text: state.page === 'ops' ? 'Alert operations center' : 'Decision history' })),
        el('div', { class: 'top-actions' },
          el('span', { class: 'env', text: `Live data · ${state.config.database || 'database'}` }),
          el('span', { class: 'notify', title: 'Alerts awaiting the analyst' }, '♧', pending ? el('i', { class: 'badge', text: pending }) : null),
          el('span', { class: 'mono', text: state.updated ? `Updated ${state.updated.toLocaleTimeString()}` : 'Loading…' }))),
      state.error ? el('div', { class: 'banner', text: state.error }) : null,
      content));
}

// ------------------------------------------------------------------ operations page
function queueCard(a) {
  const t = a.ticket;
  const sev = (t && t.severity) || a.severity;
  const question = !t ? `Status: ${STATUS_LABEL[a.status]}`
    : a.status === 'auto_closed' ? `Confirm auto-close as ${t.verdict}?` : `Accept the ${t.verdict} verdict and review ${t.title ? 'the ticket' : 'it'}?`;
  return el('article', { class: 'ticket', tabindex: 0, onclick: () => openAlert(a.alert_id), onkeydown: (e) => { if (e.key === 'Enter') openAlert(a.alert_id); } },
    el('div', { class: 'ticket-top' },
      el('span', { class: 'row-gap' }, el('span', { class: `priority ${sev === 'informational' ? 'low' : sev}`, text: sev }), sevTag(a.base_severity)),
      el('span', { class: 'mono', text: a.alert_id })),
    el('h4', { text: (t && t.title) || a.rule_name }),
    el('div', { class: 'question', text: question }),
    el('div', { class: 'ticket-meta' },
      el('span', { text: a.rule_id }), el('span', { text: a.runbook_id }),
      a.hosts ? el('span', { text: a.hosts }) : null, a.users ? el('span', { text: a.users }) : null,
      el('span', { text: fmtTime(a.created_at) })),
    el('div', { class: 'ticket-bottom' },
      t ? origin(t.origin) : el('span', { class: 'mono', text: STATUS_LABEL[a.status] }),
      t && t.confidence !== null ? el('span', { class: 'risk', text: `Confidence ${Math.round(t.confidence * 100)}%` }) : null));
}

function queuePanel() {
  const q = state.filter.toLowerCase();
  const wanted = state.status === 'review' ? REVIEW : state.status === 'all' ? null : [state.status];
  const list = state.alerts
    .filter((a) => (!wanted || wanted.includes(a.status)) && (!q || `${a.alert_id} ${a.rule_id} ${a.rule_name} ${a.hosts || ''} ${a.users || ''} ${(a.ticket && a.ticket.title) || ''}`.toLowerCase().includes(q)))
    .sort((x, y) => (SEV_RANK[(x.ticket || x).severity] ?? 5) - (SEV_RANK[(y.ticket || y).severity] ?? 5) || String(y.created_at).localeCompare(x.created_at));
  const pages = Math.max(1, Math.ceil(list.length / QUEUE_PAGE_SIZE));
  state.queuePage = Math.min(state.queuePage, pages);
  const shown = list.slice((state.queuePage - 1) * QUEUE_PAGE_SIZE, state.queuePage * QUEUE_PAGE_SIZE);
  const select = el('select', { 'aria-label': 'Status filter', onchange: (e) => { state.status = e.target.value; state.queuePage = 1; render(); } },
    [['review', 'To review'], ['all', 'All'], ...Object.entries(STATUS_LABEL)].map(([v, label]) => el('option', { value: v, selected: state.status === v, text: label })));
  const search = el('input', { placeholder: 'Search alert, rule, host, user…', value: state.filter,
    oninput: (e) => { state.filter = e.target.value; state.queuePage = 1; renderSoon(); } });
  return el('section', { class: 'panel' },
    el('div', { class: 'panel-head' },
      el('div', { class: 'panel-title' }, el('div', {}, el('h3', { text: 'Analyst queue' }), el('p', { text: 'Tickets waiting for a human decision' }))),
      el('span', { class: 'count', text: list.length })),
    el('div', { class: 'filters compact' }, search, select),
    el('div', { class: 'panel-body' }, shown.length ? shown.map(queueCard) : el('div', { class: 'empty', text: 'Nothing to review.' })),
    el('div', { class: 'queue-footer' },
      el('span', { text: `${list.length} alerts · page ${state.queuePage}/${pages}` }),
      el('div', { class: 'queue-pagination' },
        el('button', { disabled: state.queuePage <= 1, onclick: () => { state.queuePage -= 1; render(); }, text: '‹' }),
        el('button', { class: 'current', text: state.queuePage }),
        el('button', { disabled: state.queuePage >= pages, onclick: () => { state.queuePage += 1; render(); }, text: '›' }))));
}

const STAGES = ['Ingested', 'Basic checks', 'LLM', 'Analyst'];
function stageIndex(status) {
  return { new: 0, pending_llm: 1, in_llm: 2, llm_error: 2, auto_closed: 3, awaiting_analyst: 3, accepted: 4, rejected: 4 }[status] ?? 0;
}

function processingPanel() {
  const working = state.alerts.filter((a) => WORKING.includes(a.status));
  const done = state.alerts.filter((a) => ['accepted', 'rejected'].includes(a.status)).slice(0, 8);
  const row = (a) => {
    const at = stageIndex(a.status);
    return el('div', { class: 'process-card', onclick: () => openAlert(a.alert_id) },
      el('div', { class: 'process-row' }, el('b', { text: a.alert_id }), sevTag(a.severity)),
      el('div', { class: 'mono', text: `${a.rule_id} · ${a.rule_name}` }),
      el('div', { class: 'stage-line' }, STAGES.map((s, i) => el('span', { class: `stage ${i < at ? 'done' : ''} ${i === at ? 'active' : ''}`, text: s }))),
      el('span', { class: `pill ${a.status === 'llm_error' ? 'warn' : ''}`, text: STATUS_LABEL[a.status] }));
  };
  const closed = (a) => el('div', { class: 'log', onclick: () => openAlert(a.alert_id) },
    el('span', { class: 'log-time', text: a.status === 'accepted' ? '✓' : '✗' }),
    el('span', { class: 'log-text' }, el('b', { text: a.alert_id }), ` ${a.human_verdict || a.status} `, a.analyst ? human(a.analyst) : null));
  return el('section', { class: 'panel' },
    el('div', { class: 'panel-head' },
      el('div', { class: 'panel-title' }, el('div', {}, el('h3', { text: 'Processing' }), el('p', { text: 'Ingested → basic checks → LLM → analyst' }))),
      el('span', { class: 'count', text: working.length })),
    el('div', { class: 'panel-body' },
      working.length ? working.map(row) : el('div', { class: 'empty', text: 'No alert in progress. Run python -m src.main to pull new alerts.' }),
      done.length ? el('div', { class: 'chart-card' }, el('div', { class: 'chart-title', text: 'Recently decided' }), done.map(closed)) : null));
}

function bars(title, counts, labels) {
  const entries = Object.entries(counts).filter(([, n]) => n > 0);
  const max = Math.max(1, ...entries.map(([, n]) => n));
  return el('div', { class: 'chart-card' }, el('div', { class: 'chart-title', text: title }),
    el('div', { class: 'bars' }, entries.length ? entries.map(([k, n]) => el('div', { class: 'bar-row' },
      el('span', { text: (labels && labels[k]) || k }),
      el('div', { class: 'bar-track' }, el('div', { class: 'bar-fill', style: `width:${Math.round((n / max) * 100)}%` })),
      el('span', { text: n }))) : el('span', { class: 'mono', text: 'No data yet' })));
}

function statsPanel() {
  const s = state.stats;
  if (!s) return el('section', { class: 'panel' }, el('div', { class: 'empty', text: 'Loading…' }));
  const agreed = s.decisions.total ? `${Math.round((100 * (s.decisions.agreed || 0)) / s.decisions.total)}%` : '—';
  const kpi = (label, value, note) => el('div', { class: 'kpi' }, el('span', { class: 'kpi-label', text: label }), el('span', { class: 'kpi-val', text: value }), note ? el('span', { class: 'delta', text: note }) : null);
  const llm = s.llm || {};
  return el('section', { class: 'panel' },
    el('div', { class: 'panel-head' }, el('div', { class: 'panel-title' }, el('div', {}, el('h3', { text: 'Indicators' }), el('p', { text: 'From the triage tables' })))),
    el('div', { class: 'panel-body' },
      el('div', { class: 'kpis' },
        kpi('Alerts stored', s.alerts), kpi('Auto-closed by checks', s.auto_closed, s.alerts ? `${Math.round((100 * s.auto_closed) / s.alerts)}%` : ''),
        kpi('Awaiting analyst', s.by_status.awaiting_analyst + s.by_status.auto_closed), kpi('Human agrees with AI', agreed, `${s.decisions.total} verdicts`)),
      bars('Status', s.by_status, STATUS_LABEL),
      bars('Ticket verdicts (AI)', s.verdicts),
      el('div', { class: 'chart-card' }, el('div', { class: 'chart-title', text: 'LLM runs' }),
        el('div', { class: 'detail-grid' },
          el('div', {}, el('small', { text: 'Runs / valid / errors' }), `${llm.runs || 0} / ${llm.valid || 0} / ${llm.errors || 0}`),
          el('div', {}, el('small', { text: 'Average time' }), llm.avg_s ? `${Number(llm.avg_s).toFixed(1)} s` : '—'),
          el('div', {}, el('small', { text: 'Input tokens' }), llm.input_tokens || 0),
          el('div', {}, el('small', { text: 'Output tokens' }), llm.output_tokens || 0))),
      bars('Executed actions', s.executed_actions || {})));
}

function opsPage() {
  return el('div', { class: 'workspace' },
    el('div', { class: 'page-intro' },
      el('div', {}, el('h2', { text: 'Per-alert L1 triage' }), el('p', { text: 'The AI proposes; you accept or reject the verdict and each action. Nothing runs without you.' })),
      el('button', { class: 'action secondary', onclick: refresh, text: 'Refresh' })),
    el('div', { class: 'grid' }, queuePanel(), processingPanel(), statsPanel()));
}

// ------------------------------------------------------------------ history page
function historyPage() {
  const rows = state.decisions.map((d) => el('tr', { onclick: () => { state.page = 'ops'; openAlert(d.alert_id); } },
    el('td', { class: 'mono', text: fmtTime(d.decided_at) }),
    el('td', { text: d.alert_id }),
    el('td', { text: d.item === 'verdict' ? 'Verdict' : `${d.action || d.item} → ${d.target || ''}` }),
    el('td', {}, d.origin ? origin(d.origin) : null, ' ', d.ai_verdict || ''),
    el('td', {}, human(d.analyst)),
    el('td', {}, el('span', { class: `pill ${d.decision === 'accepted' ? 'success' : 'warn'}`, text: d.decision }), d.override_verdict ? ` → ${d.override_verdict}` : ''),
    el('td', { text: d.execution_status || '' }),
    el('td', { class: 'wrap', text: d.comment || '' })));
  return el('div', { class: 'history-page' },
    el('div', { class: 'page-intro' }, el('div', {}, el('h2', { text: 'Decision history' }), el('p', { text: 'What the AI proposed and what the analyst decided, newest first.' }))),
    el('div', { class: 'table-wrap' }, el('table', { class: 'table' },
      el('thead', {}, el('tr', {}, ['Decided', 'Alert', 'Item', 'AI proposal', 'Analyst', 'Decision', 'Execution', 'Comment'].map((h) => el('th', { text: h })))),
      el('tbody', {}, rows.length ? rows : el('tr', {}, el('td', { colspan: 8, class: 'empty', text: 'No decisions yet.' }))))));
}

// ------------------------------------------------------------------ investigation drawer
function section(title, ...children) {
  return el('div', { class: 'investigation-section' }, el('h3', { text: title }), children);
}
function grid(pairs) {
  return el('div', { class: 'detail-grid' }, pairs.filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => el('div', {}, el('small', { text: k }), String(v))));
}
function list(items, render) {
  return items && items.length ? el('ul', { class: 'plain' }, items.map((x) => el('li', {}, render(x)))) : el('p', { class: 'mono', text: 'None' });
}

function alertTab(d) {
  const a = d.alert, e = d.entities;
  return [
    section('Alert', grid([['Rule', `${a.rule_id} · ${a.rule_name}`], ['Severity (alert / rule)', `${a.severity} / ${a.base_severity}`],
      ['Created', fmtTime(a.created_at)], ['Runbook', a.runbook_id], ['MITRE', `${a.technique_id || ''} ${a.technique_name || ''} (${a.tactic || ''})`], ['Source', a.source_product]]),
      el('p', { class: 'untrusted-label', text: 'Description and evidence come from the detection (untrusted data):' }),
      el('div', { class: 'explanation', text: a.description || '' }), pretty(a.evidence)),
    section('Entities',
      list(e.hosts, (h) => `${h.hostname} (${h.ip || 'no IP'}, ${h.criticality}, ${h.zone_id}, ${h.business_service})`),
      list(e.users, (u) => `${u.username} · ${u.department || ''} · ${u.account_type}${u.privileged ? ' · privileged' : ''}${u.vip ? ' · VIP' : ''}`),
      list(e.indicators, (i) => `${i.indicator_type}: ${i.value} — TIP ${i.reputation || 'unknown'}`),
      e.files.length ? list(e.files, (f) => `${f.file_name || ''} ${f.sha256 || ''}`) : null,
      e.processes.length ? list(e.processes, (p) => `${p.parent_name || '?'} → ${p.name}: ${p.command_line || ''}`) : null,
      e.customers.length ? list(e.customers, (c) => `${c.customer_id} (${c.role || ''})`) : null),
    section(`Logs cited (${d.events.length})`, d.events.map((ev) => el('details', { class: 'event' },
      el('summary', { text: `${ev.event_id} · ${ev.source || 'missing'} · ${ev.event ? fmtTime(ev.event.timestamp) : ''}` }), ev.event ? pretty(ev.event) : null))),
  ];
}

function checksTab(d) {
  const c = d.checks;
  if (!c) return [section('Basic checks', el('p', { text: 'Not run yet.' }))];
  return [
    section('Outcome', el('div', { class: 'recommendation-main' },
      el('div', {}, el('small', { text: 'Deterministic checks (no LLM)' }), el('strong', { text: c.discard ? `Auto-closed as ${c.verdict} (${c.severity})` : 'Kept for the LLM' })),
      origin('auto_check'))),
    section('Guards (never auto-close)', list(c.guards, (g) => el('span', { class: 'policy', text: g }))),
    section('Explanations found', list(c.reasons, (r) => r)),
    section('Authoritative references', list(c.references, (r) => r)),
  ];
}

function llmTab(d) {
  const run = d.llm;
  if (!run) return [section('LLM', el('p', { text: d.checks && d.checks.discard ? 'Not needed: closed by the basic checks.' : 'No LLM run yet (python -m src.main --llm …).' }))];
  const entry = (e) => {
    if (e.type === 'contexto') {
      return el('div', { class: 'timeline-item' }, el('strong', { text: `Context request ${e.n}${e.comprobacion ? ' · ' + e.comprobacion : ''}${e.is_error ? ' (rejected)' : ''}` }),
        el('p', { text: e.motivo || '' }), list(e.consultas || [], (q) => `${q.consulta}(${(q.parametros || []).join(', ')}) → ${q.error ? 'error: ' + q.error : q.filas + ' rows'}`));
    }
    if (e.type === 'ticket') return el('div', { class: 'timeline-item' }, el('strong', { text: `Ticket attempt ${e.attempt}` }), el('p', { text: e.errors && e.errors.length ? 'Invalid: ' + e.errors.join('; ') : 'Valid' }));
    return el('div', { class: 'timeline-item' }, el('strong', { text: e.type }), el('p', { text: e.output || JSON.stringify(e.ticket || '') }));
  };
  return [
    section('Run', grid([['Model', run.model], ['Status', run.status], ['Valid ticket', run.valid ? 'yes' : 'no'], ['Time', run.elapsed_s ? `${run.elapsed_s} s` : '—'],
      ['Tokens in / out', `${run.usage.input_tokens || 0} / ${run.usage.output_tokens || 0}`], ['Started', fmtTime(run.started_at)]]),
      run.errors && run.errors.length ? el('div', { class: 'signal' }, el('span', { text: 'Errors' }), run.errors.map((x) => el('small', { text: x }))) : null),
    section('Transcript', el('div', { class: 'timeline' }, run.transcript.map(entry))),
    section(`Rows returned (${d.context_requests.length} requests)`, d.context_requests.map((r) => el('details', { class: 'event' },
      el('summary', { text: `#${r.n} ${r.motivo || ''}` }), pretty(r.rows)))),
  ];
}

function decisionFor(d, item) {
  const run = d.ticket && d.ticket.run_id;
  return [...d.decisions].reverse().find((x) => x.item === item && x.run_id === run);
}

function ticketTab(d) {
  if (!d.ticket) return [section('Ticket', el('p', { text: 'No ticket yet.' }))];
  const t = d.ticket.ticket;
  const actions = (t.recommended_actions || []).map((a, i) => {
    const decided = decisionFor(d, `action:${i}`);
    const exec = [...d.executed_actions].reverse().find((x) => x.run_id === d.ticket.run_id && x.action_index === i);
    return el('div', { class: 'action-card' },
      el('div', { class: 'process-row' }, el('b', { text: `${a.action} → ${a.target}` }), a.requires_approval ? el('span', { class: 'policy', text: 'Requires approval' }) : null),
      a.justification ? el('p', { text: a.justification }) : null,
      decided ? el('p', {}, human(decided.analyst), ` ${decided.decision}`, decided.comment ? ` — ${decided.comment}` : '') : null,
      exec ? el('p', { class: `exec ${exec.status}`, text: `Execution: ${exec.action} ${exec.status}${exec.api_result && exec.api_result.detail ? ' — ' + exec.api_result.detail : ''}` }) : null,
      el('div', { class: 'decision-actions' },
        el('button', { class: 'action outline', onclick: () => sendDecision({ item: `action:${i}`, decision: 'accepted', run_id: d.ticket.run_id, comment: commentValue() }), text: a.requires_approval ? 'Approve & execute' : 'Accept' }),
        el('button', { class: 'action danger', onclick: () => sendDecision({ item: `action:${i}`, decision: 'rejected', run_id: d.ticket.run_id, comment: commentValue() }), text: 'Reject' })));
  });
  return [
    section('Ticket', el('div', { class: 'recommendation-main' },
      el('div', {}, el('small', { text: t.ticket_id }), el('strong', { text: t.title })), origin(d.ticket.origin)),
      grid([['Verdict', t.verdict], ['Severity', t.severity], ['Confidence', t.confidence !== undefined ? `${Math.round(t.confidence * 100)}%` : ''],
        ['Escalate', t.escalation && t.escalation.escalate ? `yes → ${t.escalation.to || ''}` : 'no'], ['Valid', d.ticket.valid ? 'yes' : 'no']]),
      el('p', { class: 'lead', text: t.summary }), t.severity_rationale ? el('p', { text: t.severity_rationale }) : null),
    section('Evidence', list(t.evidence, (x) => `${x.event_id || ''} (${x.source || ''}): ${x.finding || ''}`)),
    t.open_questions && t.open_questions.length ? section('Open questions', list(t.open_questions, (x) => x)) : null,
    section('Recommended actions', actions.length ? actions : el('p', { class: 'mono', text: 'None proposed' })),
    section('Full ticket JSON', el('details', {}, el('summary', { text: 'Show' }), pretty(t))),
  ];
}

function decisionsTab(d) {
  return [
    section('Human verdict (alert_history)', el('p', { class: 'lead', text: d.alert_history || 'Not set — written only when an analyst accepts a verdict.' })),
    section('Decisions', el('div', { class: 'timeline' }, d.decisions.length ? [...d.decisions].reverse().map((x) => el('div', { class: 'timeline-item' },
      el('strong', {}, human(x.analyst), ` ${x.decision} ${x.item}${x.override_verdict ? ' → ' + x.override_verdict : ''}`),
      el('p', { text: `${fmtTime(x.decided_at)} · run ${x.run_id}${x.comment ? ' · ' + x.comment : ''}` }))) : el('p', { text: 'None yet.' }))),
    section('Executed actions', list(d.executed_actions, (x) => `${fmtTime(x.executed_at)} ${x.action} ${x.target}: ${x.status}${x.approval_token ? ' (approval ' + x.approval_token + ')' : ''}${x.api_result && x.api_result.detail ? ' — ' + x.api_result.detail : ''}`)),
    section('Runs', list(d.runs, (r) => `#${r.run_id} ${r.stage} · ${r.model || ''} · ${r.status}${r.valid === false ? ' · invalid' : ''} · ${fmtTime(r.started_at)}`)),
  ];
}

function commentValue() {
  const box = document.querySelector('#decision-comment');
  return box ? box.value.trim() : '';
}

function footer(d) {
  if (!d.ticket) return null;
  const t = d.ticket.ticket;
  const decided = decisionFor(d, 'verdict');
  const override = el('select', { id: 'override', 'aria-label': 'Final verdict' },
    el('option', { value: '', text: t.verdict === 'needs_more_info' ? 'Choose the final verdict…' : `Keep AI verdict (${t.verdict})` }),
    VERDICTS.filter((v) => v !== t.verdict).map((v) => el('option', { value: v, text: `Override → ${v}` })));
  const verdict = (decision) => () => sendDecision({ item: 'verdict', decision, run_id: d.ticket.run_id, comment: commentValue(),
    override_verdict: decision === 'accepted' && override.value ? override.value : null });
  return el('div', { class: 'investigation-footer' },
    decided ? el('p', { class: 'mono' }, 'Last verdict decision: ', human(decided.analyst), ` ${decided.decision}${decided.override_verdict ? ' → ' + decided.override_verdict : ''}`) : null,
    el('textarea', { id: 'decision-comment', placeholder: 'Comment for the record (optional)' }),
    el('div', { class: 'decision-actions' }, override,
      el('button', { class: 'action danger', onclick: verdict('rejected'), text: 'Reject verdict' }),
      el('button', { class: 'action primary', onclick: verdict('accepted'), text: 'Accept verdict' })));
}

function drawer() {
  const d = state.detail;
  const close = () => { state.open = null; state.detail = null; render(); };
  const tabs = [['alert', 'Alert'], ['checks', 'Basic checks'], ['llm', 'LLM transcript'], ['ticket', 'Ticket'], ['decisions', 'Decisions']];
  const body = !d ? [el('div', { class: 'empty', text: 'Loading…' })]
    : { alert: alertTab, checks: checksTab, llm: llmTab, ticket: ticketTab, decisions: decisionsTab }[state.tab](d);
  return el('div', { class: 'investigation-backdrop', onclick: (e) => { if (e.target === e.currentTarget) close(); } },
    el('aside', { class: 'investigation', role: 'dialog', 'aria-label': 'Alert investigation' },
      el('div', { class: 'investigation-head' },
        el('div', {}, el('span', { class: 'mono', text: state.open }),
          el('h2', { text: d ? ((d.ticket && d.ticket.ticket.title) || d.alert.rule_name) : '…' }),
          d ? el('div', { class: 'investigation-tags' }, sevTag(d.alert.severity), el('span', { class: 'pill', text: STATUS_LABEL[d.status] || d.status })) : null),
        el('button', { class: 'close', onclick: close, 'aria-label': 'Close', text: '×' })),
      el('div', { class: 'tabs' }, tabs.map(([id, label]) => el('button', { class: state.tab === id ? 'active' : '', onclick: () => { state.tab = id; render(); }, text: label }))),
      el('div', { class: 'investigation-body' }, body),
      d ? footer(d) : null));
}

// ------------------------------------------------------------------ render
let renderTimer = null;
function renderSoon() {
  clearTimeout(renderTimer);
  renderTimer = setTimeout(render, 150);
}

function render() {
  const focused = document.activeElement;
  const keep = focused && focused.tagName === 'INPUT' && focused.placeholder ? { placeholder: focused.placeholder, pos: focused.selectionStart } : null;
  const comment = commentValue();
  const scroll = document.querySelector('.investigation-body');
  const scrollTop = scroll ? scroll.scrollTop : 0;
  root.replaceChildren(shell(state.page === 'ops' ? opsPage() : historyPage()), state.open ? drawer() : '', state.toast ? el('div', { class: 'toast', role: 'status', text: state.toast }) : '');
  const box = document.querySelector('#decision-comment');
  if (box && comment) box.value = comment;
  const body = document.querySelector('.investigation-body');
  if (body) body.scrollTop = scrollTop;
  if (keep) {
    const input = [...document.querySelectorAll('input')].find((i) => i.placeholder === keep.placeholder);
    if (input) { input.focus(); input.setSelectionRange(keep.pos, keep.pos); }
  }
}

async function start() {
  try {
    state.config = await api('/api/config');
    if (!state.analyst && state.config.analyst) state.analyst = state.config.analyst;
  } catch (err) {
    state.error = err.message;
  }
  await refresh();
  setInterval(() => { if (!document.querySelector('textarea:focus, select:focus')) refresh(); }, REFRESH_MS);
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && state.open) { state.open = null; state.detail = null; render(); } });
start();
