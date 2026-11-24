'use strict';
/* BreachPath frontend. It only sends requests to the Java API and draws what comes back:
   every score, path, cut and benchmark is computed on the server. The DOM is built with
   textContent, never innerHTML, so host names from uploaded files cannot inject markup. */

const $ = (id) => document.getElementById(id);
const SVGNS = 'http://www.w3.org/2000/svg';

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  add(e, kids);
  return e;
}
function sv(tag, attrs, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  add(e, kids);
  return e;
}
function add(parent, kids) {
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    parent.appendChild(typeof k === 'object' ? k : document.createTextNode(String(k)));
  }
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
function fmt(n, d = 2) { return Number(n).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: 0 }); }

const state = { topo: null, result: null, selected: null, whatIf: null };

// ---- API ---------------------------------------------------------------------------------

async function api(path, options) {
  let res;
  try { res = await fetch(path, options); }
  catch (e) { throw new Error('Cannot reach the BreachPath server. Is it still running?'); }
  let data = null;
  try { data = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) throw new Error((data && data.error) || ('Request failed with status ' + res.status));
  return data;
}
const post = (p, body) => api(p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
const put = (p, body) => api(p, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

function banner(msg, info) {
  const b = $('banner');
  if (!msg) { b.hidden = true; return; }
  b.textContent = msg;
  b.className = 'banner' + (info ? ' info' : '');
  b.hidden = false;
}
function guard(fn) {
  return async (ev) => {
    if (ev && ev.preventDefault) ev.preventDefault();
    try { banner(''); await fn(ev); } catch (e) { banner(e.message); }
  };
}

// ---- tabs --------------------------------------------------------------------------------

document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
function showTab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
  document.querySelectorAll('.panel').forEach((p) => { p.hidden = p.id !== 'tab-' + name; });
}

// ---- startup -----------------------------------------------------------------------------

async function init() {
  const health = await api('/api/health');
  await loadTopology(health);
  if (health.analysed) {
    state.result = await api('/api/result');
    renderResult();
  }
}

async function loadTopology(health) {
  state.topo = await api('/api/topology');
  state.whatIf = null;
  const h = health || await api('/api/health');
  $('dataStatus').textContent = h.dataSource + ': ' + h.assets + ' assets, ' + h.links + ' links, ' + h.events
    + ' log rows, ' + h.iocs + ' IOCs, ' + h.patterns + ' patterns';
  fillChecklist($('srcList'), 'src', ['WS-Alice']);
  fillChecklist($('tgtList'), 'tgt', ['DB-PROD']);
  clear($('whatIfOut'));
  if (h.warnings && h.warnings.length) banner(h.warnings.join(' | '), true);
}

function fillChecklist(box, group, defaults) {
  clear(box);
  for (const host of state.topo.hosts) {
    const cb = el('input', { type: 'checkbox', name: group, value: host.name });
    if (defaults.includes(host.name)) cb.checked = true;
    box.appendChild(el('label', {}, cb, host.name));
  }
}
$('tgtAll').addEventListener('click', () => {
  const src = new Set(checked('src'));
  document.querySelectorAll('input[name="tgt"]').forEach((c) => { c.checked = !src.has(c.value); });
});
const checked = (group) => [...document.querySelectorAll('input[name="' + group + '"]:checked')].map((c) => c.value);

// ---- analysis ----------------------------------------------------------------------------

$('analyseForm').addEventListener('submit', guard(async () => {
  try {
    state.result = await post('/api/analyse', {
      compromised: checked('src'), targets: checked('tgt'),
      fromHour: Number($('fromHour').value), toHour: Number($('toHour').value),
    });
  } catch (e) {
    // a rejected request must not leave the previous analysis on screen as if it were current
    state.result = null; state.selected = null; state.whatIf = null;
    $('overviewBody').hidden = true; $('overviewEmpty').hidden = false;
    $('containBody').hidden = true; $('containEmpty').hidden = false;
    clear($('whatIfOut'));
    renderDetail();
    throw e;
  }
  state.selected = null;
  state.whatIf = null;
  clear($('whatIfOut'));
  renderResult();
}));

function renderResult() {
  const r = state.result;
  $('overviewEmpty').hidden = true;
  $('overviewBody').hidden = false;
  renderStats(r);
  renderIncidents(r);
  const hostRisk = riskByHost(r);
  drawMap($('mapOverview'), r, hostRisk, null);
  renderPaths(r);
  renderPlans(r);
  renderLinks(r);
  renderBloomStats(r.bloom);
  $('containEmpty').hidden = true;
  $('containBody').hidden = false;
  drawMap($('mapCut'), r, hostRisk, $('scenarioPick').value);
  if (r.warnings && r.warnings.length) banner(r.warnings.join(' | '), true);
  renderDetail();
}

function riskByHost(r) {
  const m = {};
  for (const i of r.incidents) m[i.host] = i;
  return m;
}

function renderStats(r) {
  const critical = r.incidents.filter((i) => i.priority === 'Critical').length;
  const a = r.containment.A, b = r.containment.B;
  const s = r.riskStats;
  const cards = [
    stat(r.incidents.length, 'open incidents'),
    stat(critical, 'critical', critical > 0 ? 'bad' : ''),
    stat(s.count ? s.median : '-', 'median risk score'),
    stat(s.count ? s.p90 : '-', '90th percentile risk (Quickselect, ' + fmt(s.comparisons, 0) + ' comparisons)'),
    stat(a.feasible ? a.totalCost : 'none', 'cheapest containment, scenario A', a.feasible ? '' : 'bad'),
    stat(b.feasible ? b.totalCost : 'none', 'cheapest containment, scenario B', b.feasible ? '' : 'bad'),
  ];
  add(clear($('statCards')), cards);
}
function stat(value, label, cls) {
  return el('div', { class: 'stat ' + (cls || '') }, el('div', { class: 'v' }, value), el('div', { class: 'k' }, label));
}

function renderIncidents(r) {
  const body = el('tbody');
  r.incidents.forEach((i, idx) => {
    const tr = el('tr', { class: 'pick' + (i.host === state.selected ? ' sel' : ''), tabindex: '0', 'data-host': i.host },
      el('td', { class: 'num' }, idx + 1),
      el('td', {}, i.host),
      el('td', { class: 'num' }, i.score),
      el('td', {}, el('span', { class: 'pri ' + i.priority }, i.priority)),
      el('td', { class: 'num' }, i.windowAlerts),
      el('td', { title: i.reasons.join('; ') }, i.reasons.slice(0, 2).join('; ') + (i.reasons.length > 2 ? ' (+' + (i.reasons.length - 2) + ' more)' : '')));
    const pick = () => { state.selected = i.host; renderIncidents(state.result); renderDetail(); showTab('investigate'); };
    tr.addEventListener('click', pick);
    tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') pick(); });
    body.appendChild(tr);
  });
  const table = el('table', {},
    el('thead', {}, el('tr', {}, ...['Rank', 'Host', 'Score', 'Priority', 'Alerts'].map((t, k) => el('th', { class: k === 0 || k === 2 || k === 4 ? 'num' : '' }, t)), el('th', {}, 'Why'))),
    body);
  const wrap = clear($('incidentTable'));
  if (!r.incidents.length) wrap.appendChild(el('p', { class: 'muted' }, 'No open incidents. The alert log has no rows for hosts in this network, or every incident was closed.'));
  else wrap.appendChild(el('div', { class: 'tablewrap' }, table));
  wrap.appendChild(el('p', { class: 'muted small' }, 'Red-black tree balanced: ' + (r.treeBalanced ? 'yes' : 'NO')));
}

function renderPaths(r) {
  const box = clear($('paths'));
  if (!r.attackPaths.length) box.appendChild(el('p', { class: 'tag ok' }, 'No attack path from the compromised hosts to any target.'));
  for (const p of r.attackPaths) box.appendChild(el('p', {}, el('span', { class: 'mono' }, p.path.join(' -> ')), ' (' + p.hops + ' hops)'));
  for (const u of r.unreachable) if (r.attackPaths.length) box.appendChild(el('p', { class: 'muted small' }, u.from + ' cannot reach ' + u.to));
}

// ---- investigation -----------------------------------------------------------------------

function renderDetail() {
  const box = clear($('incidentDetail'));
  const r = state.result;
  const inc = r && r.incidents.find((i) => i.host === state.selected);
  $('evidenceForm').hidden = !inc;
  $('evidenceHint').hidden = !inc;
  if (!inc) {
    box.appendChild(document.createTextNode(r ? 'Select an incident on the Overview tab.' : 'Run an analysis first.'));
    return;
  }
  box.classList.remove('muted');
  add(box, [
    el('p', {}, el('strong', {}, inc.host), '  score ', el('strong', {}, inc.score), '  ', el('span', { class: 'pri ' + inc.priority }, inc.priority)),
    el('p', { class: 'small' }, 'Alerts in window: ' + inc.windowAlerts + ', peak in one hour: ' + inc.windowPeak),
    el('ul', { class: 'plain small' }, inc.reasons.map((x) => el('li', {}, x))),
    hourChart(inc.hourly, r.window.from, r.window.to),
  ]);
}

function hourChart(values, from, to) {
  const W = 480, H = 130, pad = 22, bw = (W - pad) / 24;
  const max = Math.max(1, ...values);
  const svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Alerts per hour' });
  values.forEach((v, h) => {
    const bh = (H - pad - 8) * v / max;
    const bar = sv('rect', { x: pad + h * bw + 1, y: H - pad - bh, width: bw - 2, height: bh, class: 'bar' + (h >= from && h <= to ? ' in' : '') });
    bar.appendChild(sv('title', {}, 'hour ' + h + ': ' + v + ' alerts'));
    svg.appendChild(bar);
    if (h % 3 === 0) svg.appendChild(sv('text', { x: pad + h * bw + bw / 2, y: H - 6, 'text-anchor': 'middle', 'font-size': 10 }, h));
  });
  svg.appendChild(sv('text', { x: 0, y: 10, 'font-size': 10 }, max));
  return el('div', { class: 'chart' }, svg, el('p', { class: 'muted small' }, 'Alerts per hour; dark bars are inside the analysis window.'));
}

$('evidenceForm').addEventListener('submit', guard(async () => {
  const out = await post('/api/incidents/evidence', { host: state.selected, hour: Number($('evHour').value), delta: Number($('evDelta').value) });
  applyIncidents(out);
  banner('Evidence added: the incident was re-scored and moved in the tree.', true);
}));
$('closeIncident').addEventListener('click', guard(async () => {
  const out = await post('/api/incidents/close', { host: state.selected });
  state.selected = null;
  applyIncidents(out);
}));
function applyIncidents(out) {
  state.result.incidents = out.incidents;
  state.result.riskStats = out.riskStats;
  state.result.treeBalanced = out.treeBalanced;
  renderStats(state.result);
  renderIncidents(state.result);
  drawMap($('mapOverview'), state.result, riskByHost(state.result), null);
  renderDetail();
}

$('screenForm').addEventListener('submit', guard(async () => {
  const out = await api('/api/ioc/screen?indicator=' + encodeURIComponent($('screenInput').value));
  const verdict = out.known ? 'Known indicator' : 'Not a known indicator';
  const exactText = !out.bloomPossible ? 'skipped (the filter already ruled it out)'
    : out.exactConfirmed ? 'confirmed' : 'rejected (this was a Bloom false positive)';
  add(clear($('screenOut')), [
    el('ol', { class: 'plain' },
      el('li', {}, 'Bloom filter: ', el('strong', {}, out.bloom)),
      el('li', {}, 'Exact trie check: ', el('strong', {}, exactText)),
      el('li', {}, 'Prefix rule: ', el('strong', {}, out.prefixRuleMatch ? 'matches' : 'no match'))),
    el('p', {}, el('span', { class: 'tag ' + (out.known ? 'bad' : 'ok') }, verdict)),
    el('p', { class: 'muted small' }, out.explanation),
  ]);
  renderBloomStats(out.stats);
}));
function renderBloomStats(b) {
  $('bloomStats').textContent = 'Filter: ' + fmt(b.bits, 0) + ' bits, ' + b.hashes + ' hash functions, ' + b.items + ' indicators, target false-positive rate '
    + fmt(b.targetRate * 100, 2) + '%. Lookups so far: ' + b.lookups + ', skipped by the filter: ' + b.rejectedByFilter
    + ', false positives caught by the exact check: ' + b.falsePositives + '.';
}

$('iocForm').addEventListener('submit', guard(async () => {
  const out = await api('/api/ioc/search?prefix=' + encodeURIComponent($('iocInput').value));
  const box = clear($('iocOut'));
  box.appendChild(el('p', { class: 'muted small' }, 'Matches left after each character typed: ' + (out.narrowing.length ? out.narrowing.join(' > ') : '(none typed)')));
  if (!out.matches.length) box.appendChild(el('p', {}, 'No stored indicator starts with that prefix.'));
  else box.appendChild(el('ul', { class: 'plain mono' }, out.matches.map((m) => el('li', {}, m))));
}));
$('patForm').addEventListener('submit', guard(async () => {
  const out = await api('/api/patterns?pattern=' + encodeURIComponent($('patInput').value));
  const box = clear($('patOut'));
  if (out.patterns) {
    box.appendChild(el('p', { class: 'muted small' }, 'No pattern typed, so these are the patterns from patterns.txt:'));
    box.appendChild(el('ul', { class: 'plain mono' }, out.patterns.map((p) => el('li', {}, p.pattern + ' -> ' + (p.matches.length ? p.matches.join(', ') : '(no match)')))));
  } else if (!out.matches.length) box.appendChild(el('p', {}, 'No observed command matches ' + out.pattern + '.'));
  else box.appendChild(el('ul', { class: 'plain mono' }, out.matches.map((m) => el('li', {}, m))));
}));

// ---- containment -------------------------------------------------------------------------

function renderPlans(r) {
  const box = clear($('plans'));
  for (const key of ['A', 'B']) {
    const p = r.containment[key];
    const body = [
      el('h2', {}, el('span', {}, 'Scenario ' + key), el('span', { class: 'tag ' + (p.feasible && p.verified ? 'ok' : 'bad') },
        p.feasible ? (p.verified ? 'verified: targets unreachable' : 'NOT verified') : 'infeasible')),
      el('p', { class: 'muted small' }, p.label),
    ];
    if (p.feasible) {
      body.push(el('div', { class: 'cost' }, p.totalCost, el('span', { class: 'muted small' }, '  total cost')));
      body.push(p.actions.length ? el('ul', {}, p.actions.map((a) => el('li', {}, a.description + ' (cost ' + a.cost + ')')))
        : el('p', {}, 'Nothing to cut: no target is reachable.'));
    } else body.push(el('p', {}, p.message));
    body.push(el('p', { class: 'muted small' }, p.algorithm + ', ' + fmt(p.millis, 3) + ' ms'));
    box.appendChild(el('div', { class: 'card plan' }, body));
  }
}
$('scenarioPick').addEventListener('change', () => drawMap($('mapCut'), state.result, riskByHost(state.result), $('scenarioPick').value));

function renderLinks(r) {
  const rows = r.links.map((l) => {
    const input = el('input', { type: 'number', min: 0, max: 1000000, value: l.cost, 'aria-label': 'Cost of ' + l.from + ' to ' + l.to });
    const set = (v) => guard(async () => {
      state.result = await put('/api/links/' + l.index, { cost: Number(v()) });
      state.whatIf = null;
      renderResult();
    });
    return el('tr', {},
      el('td', {}, l.from + (l.bidirectional ? ' <-> ' : ' -> ') + l.to),
      el('td', {}, input),
      el('td', {}, l.neverCut ? el('span', { class: 'tag' }, 'never cut') : ''),
      el('td', {}, el('button', { type: 'button', onclick: set(() => input.value) }, 'Set'),
        ' ', el('button', { type: 'button', onclick: set(() => 1000000) }, 'Never cut')));
  });
  const table = el('table', {}, el('thead', {}, el('tr', {}, ...['Link', 'Cost', '', ''].map((t) => el('th', {}, t)))), el('tbody', {}, rows));
  const box = clear($('linkTable'));
  if (!rows.length) box.appendChild(el('p', { class: 'muted' }, 'This network has no links.'));
  else box.appendChild(el('div', { class: 'tablewrap' }, table));
  if (r.costChanges.length) box.appendChild(el('p', { class: 'small' }, 'Edited this session: ' + r.costChanges.join('; ')));
}
$('resetLinks').addEventListener('click', guard(async () => {
  state.result = await post('/api/links/reset');
  state.whatIf = null;
  renderResult();
}));

// ---- network map -------------------------------------------------------------------------

/* Layout only: columns by hop distance from the compromised hosts. */
function drawMap(box, r, risk, scenario) {
  const hosts = state.topo.hosts.map((h) => h.name);
  const adj = new Map(hosts.map((h) => [h, []]));
  for (const l of r.links) { adj.get(l.from).push(l.to); adj.get(l.to).push(l.from); }
  const layer = new Map();
  let queue = r.compromised.slice();
  queue.forEach((h) => layer.set(h, 0));
  while (queue.length) {
    const next = [];
    for (const h of queue) for (const n of adj.get(h)) if (!layer.has(n)) { layer.set(n, layer.get(h) + 1); next.push(n); }
    queue = next;
  }
  const maxLayer = Math.max(0, ...layer.values());
  for (const h of hosts) if (!layer.has(h)) layer.set(h, maxLayer + 1);
  const cols = [];
  for (const h of hosts) { const c = layer.get(h); (cols[c] = cols[c] || []).push(h); }
  const W = 900, rowH = 44, colW = (W - 120) / Math.max(1, cols.length - 1 || 1);
  const H = Math.max(160, Math.max(...cols.map((c) => (c || []).length)) * rowH + 40);
  const pos = new Map();
  cols.forEach((c, ci) => (c || []).forEach((h, ri) => pos.set(h, { x: 60 + (cols.length === 1 ? 0 : ci * colW), y: 28 + ri * ((H - 56) / Math.max(1, c.length - 1 || 1)) })));
  const plan = scenario ? r.containment[scenario] : null;
  const blocked = new Set(plan ? plan.blockedLinks.map((b) => b.from + '|' + b.to) : []);
  const isolated = new Set(plan ? plan.isolatedHosts : []);
  // a link a->b is on a route if a is reachable from a compromised host without passing b,
  // and a target is reachable from b without passing a (this skips dead-end branches)
  const spread = (start, fwd, avoid) => {
    const seen = new Set(start.filter((h) => h !== avoid)), q = [...seen];
    while (q.length) {
      const u = q.shift();
      for (const l of r.links) {
        const nx = fwd ? (l.from === u ? l.to : (l.bidirectional && l.to === u ? l.from : null))
                       : (l.to === u ? l.from : (l.bidirectional && l.from === u ? l.to : null));
        if (nx !== null && nx !== avoid && !seen.has(nx)) { seen.add(nx); q.push(nx); }
      }
    }
    return seen;
  };
  const step = (a, b) => spread(r.compromised, true, b).has(a) && spread(r.targets, false, a).has(b);
  const onRoute = (l) => step(l.from, l.to) || (l.bidirectional && step(l.to, l.from));
  const svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Network map' });
  for (const l of r.links) {
    const a = pos.get(l.from), b = pos.get(l.to);
    const cut = blocked.has(l.from + '|' + l.to) || blocked.has(l.to + '|' + l.from);
    svg.appendChild(sv('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: cut ? '#20242a' : (onRoute(l) ? '#e6a6a9' : '#aab5c1'), 'stroke-width': cut ? 3 : (onRoute(l) ? 3 : 1.4), 'stroke-dasharray': cut ? '6 4' : '' }));
  }
  // what the attacker can still reach once the plan is applied (only for the containment map)
  const status = new Map();
  if (plan && plan.feasible) {
    const linkOpen = (u, v) => r.links.some((l) => (l.from === u && l.to === v) || (l.bidirectional && l.from === v && l.to === u))
      && !blocked.has(u + '|' + v) && !isolated.has(v);
    const reach = new Set(r.compromised.filter((h) => !isolated.has(h)));
    const q = [...reach];
    while (q.length) {
      const u = q.shift();
      for (const h of hosts) if (!reach.has(h) && linkOpen(u, h)) { reach.add(h); q.push(h); }
    }
    for (const h of hosts) {
      if (isolated.has(h)) status.set(h, 'isolated');
      else if (r.compromised.includes(h)) status.set(h, 'compromised');
      else if (reach.has(h)) status.set(h, r.targets.includes(h) ? 'TARGET REACHABLE' : 'still reachable');
      else status.set(h, r.targets.includes(h) ? 'protected' : 'cut off');
    }
    const others = hosts.filter((h) => !r.compromised.includes(h));
    const open = others.filter((h) => reach.has(h));
    $('cutSummary').textContent = 'After scenario ' + scenario + ': ' + (others.length - open.length) + ' of ' + others.length
      + ' other hosts are cut off from the attacker, ' + open.length + ' still reachable'
      + (open.length ? ' (' + open.join(', ') + ')' : '') + '. All protected targets are '
      + (r.targets.some((t) => reach.has(t)) ? 'NOT all safe.' : 'safe.');
  } else if (scenario) {
    $('cutSummary').textContent = plan ? 'No plan is possible for this selection.' : '';
  }
  const color = { Critical: '#a4262c', High: '#c4561f', Medium: '#b88a00', Low: '#9aa6b2' };
  const meta = new Map(state.topo.hosts.map((h) => [h.name, h]));
  for (const h of hosts) {
    const p = pos.get(h), m = meta.get(h), inc = risk[h];
    const isSrc = r.compromised.includes(h), isTgt = r.targets.includes(h);
    const fill = inc ? color[inc.priority] : '#ffffff';
    const stroke = isSrc ? '#a4262c' : '#20242a';
    const g = sv('g', {});
    g.appendChild(sv('title', {}, h + ' (' + m.type + ')\nisolation cost ' + m.isolationCost + (m.internetFacing ? '\ninternet-facing' : '') + (m.patched ? '' : '\nunpatched') + (inc ? '\nrisk ' + inc.score + ' ' + inc.priority : '')));
    g.appendChild(isTgt ? sv('rect', { x: p.x - 9, y: p.y - 9, width: 18, height: 18, fill, stroke, 'stroke-width': 2 })
      : sv('circle', { cx: p.x, cy: p.y, r: 9, fill, stroke, 'stroke-width': isSrc ? 3.5 : 1.5 }));
    if (isolated.has(h)) {
      g.appendChild(sv('line', { x1: p.x - 8, y1: p.y - 8, x2: p.x + 8, y2: p.y + 8, stroke: '#a4262c', 'stroke-width': 3 }));
      g.appendChild(sv('line', { x1: p.x - 8, y1: p.y + 8, x2: p.x + 8, y2: p.y - 8, stroke: '#a4262c', 'stroke-width': 3 }));
    }
    g.appendChild(sv('text', { x: p.x, y: p.y - 13, 'text-anchor': 'middle' }, h));
    if (status.has(h)) {
      const s = status.get(h);
      const cls = (s === 'cut off' || s === 'protected') ? 'status-cut' : (s === 'isolated' || s === 'compromised' ? 'status-note' : 'status-open');
      g.appendChild(sv('text', { x: p.x, y: p.y + 24, 'text-anchor': 'middle', 'font-size': 10, class: cls }, s));
    }
    svg.appendChild(g);
  }
  clear(box).appendChild(svg);
}

// ---- what-if -----------------------------------------------------------------------------

$('loadWhatIf').addEventListener('click', guard(async () => {
  const out = await api('/api/whatif');
  const rows = out.rows.map((w) => el('tr', {},
    el('td', {}, w.host), el('td', {}, w.type),
    el('td', {}, w.exposedAndUnpatched ? el('span', { class: 'tag bad' }, 'internet-facing, unpatched') : (w.internetFacing ? 'internet-facing' : (w.patched ? '' : 'unpatched'))),
    el('td', { class: 'num' }, w.reaches ? w.hops : 'cannot reach'),
    el('td', { class: 'num' }, w.feasibleA ? w.costA : 'infeasible'),
    el('td', { class: 'num' }, w.feasibleB ? w.costB : 'infeasible')));
  const table = el('table', {}, el('thead', {}, el('tr', {}, el('th', {}, 'Host'), el('th', {}, 'Type'), el('th', {}, 'Exposure'),
    el('th', { class: 'num' }, 'Steps to target'), el('th', { class: 'num' }, 'Cost A'), el('th', { class: 'num' }, 'Cost B'))), el('tbody', {}, rows));
  clear($('whatIfOut')).appendChild(el('div', { class: 'tablewrap' }, table));
}));

// ---- data --------------------------------------------------------------------------------

$('uploadForm').addEventListener('submit', guard(async () => {
  const read = async (id) => { const f = $(id).files[0]; return f ? await f.text() : null; };
  const body = { assets: await read('fAssets'), edges: await read('fEdges'), events: await read('fEvents'), iocs: await read('fIocs'), patterns: await read('fPatterns') };
  for (const [k, v] of Object.entries(body)) if (v == null && !['iocs', 'patterns'].includes(k)) throw new Error('Choose the ' + k + ' file first.');
  const health = await post('/api/data', body);
  await afterDataChange(health, 'Data uploaded and validated.');
}));
$('resetData').addEventListener('click', guard(async () => {
  const health = await post('/api/data/reset');
  await afterDataChange(health, 'Sample data reloaded.');
}));
async function afterDataChange(health, message) {
  state.result = null; state.selected = null;
  await loadTopology(health);
  $('overviewBody').hidden = true; $('overviewEmpty').hidden = false;
  $('containBody').hidden = true; $('containEmpty').hidden = false;
  renderDetail();
  if (health.analysed) { state.result = await api('/api/result'); renderResult(); }
  showTab('overview');
  banner(message + (health.warnings.length ? ' ' + health.warnings.join(' | ') : ''), true);
}
$('downloadReport').addEventListener('click', guard(async () => {
  const res = await fetch('/api/report');
  if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || 'Could not build the report'); }
  const url = URL.createObjectURL(await res.blob());
  const a = el('a', { href: url, download: 'breachpath-report.html' });
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}));

// ---- benchmarks --------------------------------------------------------------------------

async function runBench(profile) {
  const buttons = [$('runBench'), $('runBenchFull')];
  buttons.forEach((b) => { b.disabled = true; });
  $('benchState').textContent = 'Running on the server...';
  try {
    const out = await api('/api/benchmarks?profile=' + profile);
    renderBench(out);
    $('benchState').textContent = 'Done (' + out.profile + ' profile). ' + out.note;
  } finally { buttons.forEach((b) => { b.disabled = false; }); }
}
$('runBench').addEventListener('click', guard(() => runBench('quick')));
$('runBenchFull').addEventListener('click', guard(() => runBench('full')));

function renderBench(out) {
  const box = clear($('benchOut'));
  for (const e of out.experiments) {
    const rows = e.rows.map((r) => el('tr', {},
      el('td', {}, r.size), el('td', { class: 'num' }, fmt(r.techniqueMs)), el('td', { class: 'num' }, fmt(r.baselineMs)),
      el('td', { class: 'num' }, fmt(r.speedup, 1) + 'x'),
      el('td', {}, el('span', { class: 'tag ' + (r.match ? 'ok' : 'bad') }, r.match ? 'same answer' : 'DIFFERENT')),
      el('td', { class: 'small' }, r.detail)));
    const table = el('table', {}, el('thead', {}, el('tr', {}, el('th', {}, 'Size'), el('th', { class: 'num' }, 'Technique ms'), el('th', { class: 'num' }, 'Baseline ms'),
      el('th', { class: 'num' }, 'Speed-up'), el('th', {}, 'Check'), el('th', {}, 'Detail'))), el('tbody', {}, rows));
    box.appendChild(el('div', { class: 'card bench' },
      el('h2', {}, e.technique + ' vs ' + e.baseline), el('p', { class: 'muted small' }, e.workload),
      el('div', { class: 'tablewrap' }, table), benchChart(e), el('p', { class: 'small cmp' }, e.conclusion)));
  }
}

/* Two bars per size on a logarithmic scale, so a 10,000x gap and a 1.1x gap can share one chart. */
function benchChart(e) {
  const W = 640, rowH = 36, H = e.rows.length * rowH + 22, left = 120;
  const logv = (ms) => Math.log10(Math.max(ms, 0.001)) + 3;
  const top = Math.max(...e.rows.flatMap((r) => [logv(r.techniqueMs), logv(r.baselineMs)]), 1);
  const svg = sv('svg', { viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Technique and baseline times' });
  e.rows.forEach((r, i) => {
    const y = 6 + i * rowH;
    svg.appendChild(sv('text', { x: 0, y: y + 20, 'font-size': 11 }, r.size.length > 18 ? r.size.slice(0, 18) : r.size));
    [[r.techniqueMs, 'bar in', 'technique'], [r.baselineMs, 'bar', 'baseline']].forEach(([ms, cls, name], k) => {
      const w = Math.max(2, (W - left - 80) * logv(ms) / top);
      svg.appendChild(sv('rect', { x: left, y: y + k * 14, width: w, height: 11, class: cls }));
      svg.appendChild(sv('text', { x: left + w + 4, y: y + k * 14 + 10, 'font-size': 10 }, name + ' ' + fmt(ms) + ' ms'));
    });
  });
  svg.appendChild(sv('text', { x: left, y: H - 4, 'font-size': 10 }, 'Bar length is logarithmic (longer is slower).'));
  return el('div', { class: 'chart' }, svg);
}

init().catch((e) => banner(e.message));