/**
 * RepoSentinel AI — Frontend Application
 * Vanilla ES2022, no frameworks, no CDN dependencies.
 */

'use strict';

// ── API base (same-origin) ─────────────────────────────────
const API = '';

// ── Global state ──────────────────────────────────────────
const state = {
  currentRepo:  null,   // { owner, repo }
  currentScan:  null,   // scan record
  mcpTools:     [],
  scanResults:  null,
  history:      [],
  liveState:    null,
  chatContext:  null,   // { owner, repo } set after a scan
  refreshTimer: null,
};

// ── Entry point ────────────────────────────────────────────
async function init() {
  setupEventListeners();
  showSection('scan');

  // Load everything in parallel
  await Promise.allSettled([
    loadLiveState(),
    loadMCPTools(),
    loadHistory(),
  ]);

  // Auto-refresh live state every 15 s
  state.refreshTimer = setInterval(loadLiveState, 15_000);
}

// ═══════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════

async function apiFetch(path, options = {}) {
  const url = `${API}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers ?? {}) },
    ...options,
  });
  if (!res.ok) {
    let msg = `API error ${res.status}`;
    try {
      const j = await res.json();
      const raw = j.detail ?? j.error ?? j.message;
      if (typeof raw === 'string') msg = raw;
      else if (raw && typeof raw === 'object') msg = raw.error ?? raw.message ?? JSON.stringify(raw);
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Core features
// ═══════════════════════════════════════════════════════════

/** POST /api/scan – run a full repository security scan */
async function scanRepo(owner, repo) {
  showLoading(true);
  clearScanUI();

  const progressEl = document.getElementById('scan-progress');
  progressEl?.classList.add('active');
  setProgressStep('step-fetch', 'active');

  try {
    const data = await apiFetch('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ owner, repo }),
    });

    state.currentRepo  = { owner, repo };
    state.currentScan  = data;
    state.scanResults  = data;
    state.chatContext  = { owner, repo };

    setProgressStep('step-fetch', 'done');
    setProgressStep('step-osv', 'done');
    setProgressStep('step-gh', 'done');

    const commitRepoEl = document.getElementById('commit-repo-input');
    if (commitRepoEl && !commitRepoEl.value.trim()) {
      commitRepoEl.value = `${owner}/${repo}`;
    }

    renderScanResults(data);
    renderGithubCorrelation(data);
    renderTraceFromScan(data);

    // Update nav badges
    const vulnCount = data?.vulnerabilities?.length ?? 0;
    updateNavBadge('nav-vulnerabilities', vulnCount > 0 ? vulnCount : null);

    // Reload history to include the new scan
    await loadHistory();

    showBanner(`Scan complete — ${vulnCount} vulnerabilities found for ${owner}/${repo}`, 'success');
  } catch (err) {
    showError(err.message);
    setProgressStep('step-fetch', 'error');
  } finally {
    showLoading(false);
    setTimeout(() => progressEl?.classList.remove('active'), 2000);
  }
}

/** GET /api/mcp-tools – list all registered MCP tools */
async function loadMCPTools() {
  try {
    const data = await apiFetch('/api/mcp-tools');
    state.mcpTools = data?.tools ?? [];
    renderMCPTools(data);
  } catch (err) {
    renderMCPToolsError(err.message);
  }
}

/** POST /api/refresh-tools – re-discover MCP tools */
async function refreshMCPTools() {
  const btn = document.getElementById('btn-refresh-tools');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Refreshing…'; }
  try {
    const data = await apiFetch('/api/refresh-tools', { method: 'POST' });
    state.mcpTools = data?.tools ?? [];
    renderMCPTools(data);
    showBanner(`MCP tools refreshed (${state.mcpTools.length} tools discovered)`, 'success');
  } catch (err) {
    showError(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '⟳ Refresh Tools'; }
  }
}

/** POST /api/chat – send a message to the AI copilot */
async function sendChatMessage(message, owner, repo) {
  if (!message.trim()) return;

  renderChatMessage('user', message, null);
  scrollChatToBottom();

  const thinkingId = renderThinkingBubble();

  try {
    const payload = { message };
    if (owner) payload.owner = owner;
    if (repo)  payload.repo  = repo;

    const data = await apiFetch('/api/chat', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    removeThinkingBubble(thinkingId);
    const trace = data.execution_trace ?? data.trace ?? [];
    renderChatMessage('agent', data.response ?? data.content ?? '', trace, data);

    // Append sources / tool trace
    if (trace.length) {
      appendTraceItems(trace);
      updateNavBadge('nav-trace', (parseInt(document.getElementById('nav-trace')?.dataset.count ?? '0', 10) + trace.length) || null);
    }
  } catch (err) {
    removeThinkingBubble(thinkingId);
    renderChatMessage('agent', `⚠️ Error: ${err.message}`, null);
  }

  scrollChatToBottom();
}

/** GET /api/history – load scan history */
async function loadHistory() {
  try {
    const data = await apiFetch('/api/history');
    state.history = data?.records ?? data ?? [];
    renderHistory(state.history);
  } catch (err) {
    renderHistoryError(err.message);
  }
}

/** GET /api/live-state – refresh service status pills */
async function loadLiveState() {
  try {
    const data = await apiFetch('/api/live-state');
    state.liveState = data;
    renderLiveState(data);
  } catch {
    // Silently mark all as unknown on failure
    renderLiveState(null);
  }
}

// ═══════════════════════════════════════════════════════════
// Render: Scan Results
// ═══════════════════════════════════════════════════════════

function renderScanResults(data) {
  if (!data) return;

  const vulns     = data.vulnerabilities ?? [];
  const deps      = data.dependencies    ?? [];
  const stats     = data.stats           ?? {};
  const owner     = data.owner           ?? state.currentRepo?.owner ?? '';
  const repo      = data.repo            ?? state.currentRepo?.repo  ?? '';
  const scannedAt = data.scanned_at      ?? data.timestamp           ?? null;

  // ── Result header
  const headerEl = document.getElementById('scan-result-header');
  if (headerEl) {
    headerEl.classList.remove('hidden');
    headerEl.innerHTML = `
      <span class="scan-repo-name">📦 ${escHtml(owner)}/${escHtml(repo)}</span>
      ${scannedAt ? `<span class="scan-timestamp">Scanned ${formatDate(scannedAt)}</span>` : ''}
      <span class="ml-auto">
        <span class="tag">${deps.length} dependencies</span>
      </span>`;
  }

  // ── Stat cards
  const critical = countSeverity(vulns, 'CRITICAL');
  const high     = countSeverity(vulns, 'HIGH');
  const medium   = countSeverity(vulns, 'MEDIUM');
  const low      = countSeverity(vulns, 'LOW');
  const unresolved = data.unresolved_count ?? deps.filter(d => d.is_resolved === false).length;
  const openPRs  = data.open_remediation_prs ?? (data.github?.pull_requests?.filter(p => p.state === 'open').length ?? 0);

  const statData = [
    { label: 'Dependencies',   value: data.total_dependencies ?? deps.length, cls: 'info', id: 'stat-deps' },
    { label: 'Vulnerabilities',value: data.total_vulnerabilities ?? vulns.length, cls: 'critical', id: 'stat-vulns' },
    { label: 'Critical',       value: critical,         cls: 'critical', id: 'stat-critical' },
    { label: 'High',           value: high,             cls: 'high',     id: 'stat-high' },
    { label: 'Medium',         value: medium,           cls: 'medium',   id: 'stat-medium' },
    { label: 'Low',            value: low,              cls: 'low',      id: 'stat-low' },
    { label: 'Unresolved Ver', value: unresolved,       cls: unresolved > 0 ? 'medium' : '', id: 'stat-unresolved' },
    { label: 'Remediation PRs',value: openPRs,          cls: 'info',     id: 'stat-prs' },
  ];

  const grid = document.getElementById('stat-grid-overview');
  if (grid) {
    grid.innerHTML = statData.map(s => `
      <div class="stat-card ${s.cls}" id="${s.id}">
        <div class="stat-label">${escHtml(s.label)}</div>
        <div class="stat-value ${s.cls}">${s.value}</div>
      </div>`).join('');
  }

  // ── Vulnerability table (section-scan + section-vulnerabilities)
  ['vuln-table-scan', 'vuln-table-vulns'].forEach(id => {
    const container = document.getElementById(id);
    if (!container) return;
    container.innerHTML = vulns.length
      ? buildVulnTable(vulns)
      : emptyState('🛡️', 'No vulnerabilities found', 'This repository has no known vulnerabilities in its dependencies.');
  });
}

function buildVulnTable(vulns) {
  const thead = `
    <thead>
      <tr>
        <th class="sortable" data-col="package">Package</th>
        <th class="sortable" data-col="version">Version</th>
        <th class="sortable" data-col="id">ID</th>
        <th class="sortable" data-col="severity">Severity</th>
        <th>Affected Range</th>
        <th>Fixed Version</th>
        <th>Source</th>
      </tr>
    </thead>`;

  const rows = vulns.map((v, i) => `
    <tr data-idx="${i}">
      <td class="cell-package">${escHtml(v.package ?? v.name ?? '—')}</td>
      <td class="cell-version">${escHtml(v.version ?? '—')}</td>
      <td class="cell-id"><a href="${buildVulnLink(v)}" target="_blank" rel="noopener">${escHtml(v.id ?? v.vuln_id ?? '—')}</a></td>
      <td>${severityBadge(v.severity)}</td>
      <td class="cell-range">${escHtml(v.affected_range ?? v.ranges ?? '—')}</td>
      <td class="cell-fixed">${escHtml(v.fixed_version ?? v.fixed ?? '—')}</td>
      <td class="cell-source">${escHtml(v.source ?? v.database ?? 'OSV')}</td>
    </tr>`).join('');

  return `<div class="table-wrapper"><table class="vuln-table">${thead}<tbody>${rows}</tbody></table></div>`;
}

function buildVulnLink(v) {
  const id = v.id ?? v.vuln_id ?? '';
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
  if (id.startsWith('CVE-'))  return `https://nvd.nist.gov/vuln/detail/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function countSeverity(vulns, sev) {
  return vulns.filter(v => (v.severity ?? '').toUpperCase() === sev).length;
}

// ═══════════════════════════════════════════════════════════
// Render: GitHub Correlation
// ═══════════════════════════════════════════════════════════

function renderGithubCorrelation(data) {
  const container = document.getElementById('github-cards');
  if (!container) return;

  const issues = data?.github?.issues ?? [];
  const prs    = data?.github?.pull_requests ?? data?.github?.prs ?? [];
  const all    = [
    ...issues.map(i => ({ ...i, _type: 'issue' })),
    ...prs.map(p => ({ ...p, _type: 'pr' })),
  ];

  if (!all.length) {
    container.innerHTML = emptyState('🐙', 'No GitHub items found', 'No related issues or pull requests were returned for this repository.');
    return;
  }

  container.innerHTML = `<div class="issue-grid">${all.map(buildIssueCard).join('')}</div>`;
}

function buildIssueCard(item) {
  const type  = item._type;
  const state_ = (item.state ?? 'open').toLowerCase();
  const merged = !!item.merged_at;
  const icon   = type === 'pr'
    ? (merged ? '↗' : state_ === 'closed' ? '✕' : '↗')
    : (state_ === 'closed' ? '✓' : '●');
  const iconCls = type === 'pr'
    ? (merged ? 'pr-merged' : state_ === 'closed' ? 'pr-closed' : 'pr-open')
    : (state_ === 'closed' ? 'issue-closed' : 'issue-open');

  const labels = (item.labels ?? []).slice(0, 3).map(l => {
    const color = l.color ? `#${l.color}` : 'var(--border-muted)';
    const fg    = l.color ? contrastColor(l.color) : 'var(--text-secondary)';
    return `<span class="issue-label" style="background:${color}22;border-color:${color}66;color:${fg}">${escHtml(l.name ?? l)}</span>`;
  }).join('');

  const url   = item.html_url ?? item.url ?? '#';
  const title = item.title ?? '(No title)';
  const num   = item.number ? `#${item.number}` : '';
  const user  = item.user?.login ?? item.author ?? '';
  const body  = item.body ? item.body.slice(0, 160) : '';

  const corr = item.correlation_status;
  const corrTag = corr === 'confirmed_match'
    ? '<span class="severity-badge critical">Confirmed Match</span>'
    : corr === 'possible_match'
      ? '<span class="severity-badge medium">Possible Match</span>'
      : '';
  const matchedIds = (item.matched_vulnerability_ids ?? []).map(v => `<span class="tag">${escHtml(v)}</span>`).join('');

  return `
    <div class="issue-card">
      <div class="issue-card-header">
        <div class="issue-type-icon ${iconCls}">${icon}</div>
        <div class="issue-card-title">
          <a href="${escHtml(url)}" target="_blank" rel="noopener">${escHtml(title)}</a>
        </div>
      </div>
      <div class="issue-card-meta">
        <span class="issue-num">${escHtml(num)}</span>
        ${corrTag}
        ${matchedIds}
        ${user ? `<span>by ${escHtml(user)}</span>` : ''}
        ${labels}
        <span class="tag">${type === 'pr' ? 'Pull Request' : 'Issue'}</span>
        <span class="tag">${escHtml(state_)}</span>
      </div>
      ${body ? `<div class="issue-card-body mt-8">${escHtml(body)}…</div>` : ''}
    </div>`;
}

function contrastColor(hex) {
  try {
    const r = parseInt(hex.slice(0,2),16);
    const g = parseInt(hex.slice(2,4),16);
    const b = parseInt(hex.slice(4,6),16);
    return (r*299 + g*587 + b*114)/1000 > 128 ? '#0d1117' : '#e6edf3';
  } catch { return 'var(--text-primary)'; }
}

// ═══════════════════════════════════════════════════════════
// Render: MCP Tools
// ═══════════════════════════════════════════════════════════

function renderMCPTools(payload) {
  const tools = Array.isArray(payload) ? payload : (payload?.tools ?? []);
  const serverContainer = document.getElementById('mcp-server-cards');
  const toolContainer   = document.getElementById('mcp-tool-cards');
  const ghStatus = payload?.github_server_status ?? 'unknown';
  const osvStatus = payload?.osv_server_status ?? 'unknown';
  const refreshedAt = payload?.last_refreshed_at ? formatDate(payload.last_refreshed_at) : 'Never';

  const servers = {
    'github-service-mcp': { status: ghStatus, tools: [] },
    'osv-service-mcp': { status: osvStatus, tools: [] },
  };
  for (const t of tools) {
    const srv = t.server ?? t.server_name ?? t.mcp_server ?? 'Unknown';
    if (!servers[srv]) servers[srv] = { status: 'connected', tools: [] };
    servers[srv].tools.push(t);
  }

  if (serverContainer) {
    serverContainer.innerHTML = Object.entries(servers).map(([srvName, info]) => {
      const ok = info.status === 'connected';
      return `
      <div class="server-card">
        <div class="server-card-header">
          <div class="server-status-dot ${ok ? 'connected' : 'error'}"></div>
          <span class="server-name">${escHtml(srvName)}</span>
          <span class="server-type">${escHtml(info.status)} · ${info.tools.length} tool${info.tools.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="server-meta">
          <div>Last refresh: ${escHtml(refreshedAt)}</div>
          <div>Tools: ${info.tools.length ? info.tools.map(t => `<code>${escHtml(t.name ?? t.tool_name ?? '')}</code>`).join(', ') : '<span class="text-muted">None discovered</span>'}</div>
        </div>
      </div>`;
    }).join('');
  }

  if (!tools.length) {
    if (toolContainer) {
      toolContainer.innerHTML = emptyState('🔧', 'No tools discovered', 'Start github_service (8001) and osv_service (8002), then click Refresh Tools.');
    }
    return;
  }

  if (toolContainer) {
    toolContainer.innerHTML = tools.map(t => {
      const name   = t.name ?? t.tool_name ?? 'unknown';
      const server = t.server ?? t.server_name ?? t.mcp_server ?? '';
      const desc   = t.description ?? t.desc ?? '';
      const icon   = toolIcon(name);
      return `
        <div class="tool-card">
          <div class="tool-card-header">
            <div class="tool-card-icon">${icon}</div>
            <div class="tool-card-name">${escHtml(name)}</div>
          </div>
          <div class="tool-card-server">via ${escHtml(server)}</div>
          <div class="tool-card-desc">${escHtml(desc) || '<span class="text-muted">No description</span>'}</div>
        </div>`;
    }).join('');
  }
}

function renderMCPToolsError(msg) {
  const c = document.getElementById('mcp-tool-cards');
  if (c) c.innerHTML = emptyState('⚠️', 'Failed to load tools', msg);
}

function toolIcon(name) {
  const n = name.toLowerCase();
  if (n.includes('search'))    return '🔍';
  if (n.includes('vuln') || n.includes('osv')) return '🛡️';
  if (n.includes('issue') || n.includes('github') || n.includes('gh')) return '🐙';
  if (n.includes('pr') || n.includes('pull')) return '↗';
  if (n.includes('dep') || n.includes('package')) return '📦';
  if (n.includes('scan'))      return '🔬';
  if (n.includes('list'))      return '📋';
  if (n.includes('create'))    return '✏️';
  return '🔧';
}

// ═══════════════════════════════════════════════════════════
// Render: Chat
// ═══════════════════════════════════════════════════════════

function renderChatMessage(role, content, trace, metaData = null) {
  const history = document.getElementById('chat-history');
  if (!history) return;

  // Remove welcome empty state if present
  const welcome = history.querySelector('.empty-state');
  if (welcome) welcome.remove();

  const msgId   = `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const isUser  = role === 'user';

  const sourcesHtml = (!isUser && trace?.length) ? `
    <div class="chat-sources">
      <div class="chat-sources-label">MCP Tools Executed</div>
      ${trace.map(t => `<span class="chat-source-tag">🔧 ${escHtml(t.tool ?? t.tool_name ?? t.name ?? '')}</span>`).join('')}
    </div>` : '';

  const extSources = (!isUser && metaData?.sources?.length)
    ? `<div class="chat-sources"><div class="chat-sources-label">Verified Sources</div>${metaData.sources.filter(s => s.url).slice(0, 6).map(s => `<a class="chat-source-tag" href="${escHtml(s.url)}" target="_blank" rel="noopener">🔗 ${escHtml(s.id || s.source_system || s.type)}</a>`).join('')}</div>`
    : '';

  const modelInfo = (!isUser && metaData?.model_used)
    ? ` · ${escHtml(metaData.model_used)}${metaData.total_duration_ms ? ` · ${formatDuration(metaData.total_duration_ms)}` : ''}`
    : '';

  const html = `
    <div class="chat-message ${isUser ? 'user' : 'agent'}" id="${msgId}">
      <div class="chat-bubble">
        ${renderMarkdownLite(content)}
        ${sourcesHtml}
        ${extSources}
      </div>
      <div class="chat-meta">${isUser ? 'You' : '🤖 Copilot'} · ${timeStr}${modelInfo}</div>
    </div>`;

  history.insertAdjacentHTML('beforeend', html);
  scrollChatToBottom();
  return msgId;
}

function renderThinkingBubble() {
  const history = document.getElementById('chat-history');
  if (!history) return null;
  const id = `thinking-${Date.now()}`;
  history.insertAdjacentHTML('beforeend', `
    <div class="chat-message agent" id="${id}">
      <div class="chat-bubble">
        <span class="text-muted">
          <span class="loading-spinner" style="width:12px;height:12px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:6px;"></span>
          Thinking…
        </span>
      </div>
    </div>`);
  scrollChatToBottom();
  return id;
}

function removeThinkingBubble(id) {
  if (id) document.getElementById(id)?.remove();
}

function scrollChatToBottom() {
  const h = document.getElementById('chat-history');
  if (h) h.scrollTop = h.scrollHeight;
}

/** Minimal markdown-lite renderer for chat bubbles */
function renderMarkdownLite(text) {
  if (!text) return '';
  let s = escHtml(text);
  // Code blocks
  s = s.replace(/```[\w]*\n?([\s\S]*?)```/g, (_, c) => `<pre><code>${c}</code></pre>`);
  // Inline code
  s = s.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
  // Bold
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Italic
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // Bullet lists
  s = s.replace(/^- (.+)$/gm, '<li>$1</li>').replace(/((<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>');
  // Numbered lists
  s = s.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
  // Newlines
  s = s.replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>');
  return `<p>${s}</p>`;
}

// ═══════════════════════════════════════════════════════════
// Render: History
// ═══════════════════════════════════════════════════════════

function renderHistory(records) {
  const container = document.getElementById('history-container');
  if (!container) return;

  if (!records?.length) {
    container.innerHTML = emptyState('📜', 'No scan history', 'Run your first repository scan to populate the history.');
    return;
  }

  const rows = records.map((r, i) => {
    const repo    = r.owner && r.repo ? `${r.owner}/${r.repo}` : (r.repository ?? r.repo ?? '—');
    const vulns   = r.vulnerability_count ?? r.vuln_count ?? r.vulnerabilities?.length ?? '—';
    const when    = r.scanned_at ?? r.timestamp ?? r.created_at ?? null;
    const status  = r.status ?? 'completed';
    const critical = r.critical ?? countSeverity(r.vulnerabilities ?? [], 'CRITICAL');
    return `
      <tr data-idx="${i}" title="Click to view details">
        <td class="cell-package">${escHtml(repo)}</td>
        <td>${when ? formatDate(when) : '—'}</td>
        <td>${escHtml(String(vulns))}</td>
        <td>${critical > 0 ? `<span class="text-critical">⬤ ${critical}</span>` : '<span class="text-low">✓ 0</span>'}</td>
        <td><span class="tag">${escHtml(status)}</span></td>
      </tr>`;
  }).join('');

  container.innerHTML = `
    <div class="table-wrapper">
      <table class="history-table">
        <thead>
          <tr>
            <th>Repository</th>
            <th>Scanned At</th>
            <th>Vulnerabilities</th>
            <th>Critical</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;

  // Click-to-view
  container.querySelectorAll('tbody tr').forEach(tr => {
    tr.addEventListener('click', async () => {
      const idx = parseInt(tr.dataset.idx, 10);
      const rec = records[idx];
      if (!rec) return;
      try {
        const full = rec.id ? await apiFetch(`/api/history/${rec.id}`) : rec;
        state.currentScan = full;
        state.scanResults = full;
        state.currentRepo = { owner: full.owner ?? '', repo: full.repo ?? '' };
        state.chatContext = { owner: full.owner ?? '', repo: full.repo ?? '' };
        renderScanResults(full);
        renderGithubCorrelation(full);
        showSection('scan');
        showBanner(`Loaded persisted scan for ${state.currentRepo.owner}/${state.currentRepo.repo}`, 'info');
      } catch (err) {
        showError(err.message);
      }
    });
  });
}

function renderHistoryError(msg) {
  const c = document.getElementById('history-container');
  if (c) c.innerHTML = emptyState('⚠️', 'Failed to load history', msg);
}

// ═══════════════════════════════════════════════════════════
// Render: Live State (header pills)
// ═══════════════════════════════════════════════════════════

function renderLiveState(data) {
  const services = {
    'github-service': 'GitHub Service',
    'osv-service':    'OSV Service',
    'github-mcp':     'GitHub MCP',
    'osv-mcp':        'OSV MCP',
    'groq':           'Groq',
    'gemini':         'Gemini',
  };

  for (const [key, label] of Object.entries(services)) {
    const el = document.getElementById(`pill-${key}`);
    if (!el) continue;

    const svcData = data?.services?.[key] ?? data?.[key] ?? null;
    const status  = svcData?.status ?? (data ? 'unknown' : 'unknown');

    el.className = 'status-pill';
    if (status === 'ok' || status === 'connected' || status === 'healthy' || status === true) {
      el.classList.add('ok');
    } else if (status === 'warn' || status === 'degraded') {
      el.classList.add('warn');
    } else if (status === 'error' || status === 'disconnected' || status === false) {
      el.classList.add('err');
    } else {
      el.classList.add('unk');
    }
  }
}

// ═══════════════════════════════════════════════════════════
// Render: Execution Trace
// ═══════════════════════════════════════════════════════════

function renderTraceFromScan(data) {
  const trace = data?.trace ?? data?.execution_trace ?? [];
  if (trace.length) appendTraceItems(trace);
}

function appendTraceItems(traceItems) {
  const container = document.getElementById('trace-list');
  if (!container) return;

  // Remove empty state
  container.querySelector('.empty-state')?.remove();

  const offset = container.querySelectorAll('.trace-item').length;

  traceItems.forEach((t, i) => {
    const el    = document.createElement('div');
    el.className = 'trace-item';
    const step   = offset + i + 1;
    const dur    = t.duration_ms != null ? formatDuration(t.duration_ms) : (t.duration ?? '');
    const tool   = t.tool ?? t.tool_name ?? t.name ?? 'unknown';
    const server = t.server ?? t.server_name ?? t.mcp_server ?? '';
    const ok     = t.success !== false && t.error == null;
    const args   = t.args ?? t.input ?? t.arguments ?? null;

    el.innerHTML = `
      <div class="trace-step">${step}</div>
      <div class="trace-body">
        <div class="trace-header-row">
          <span class="trace-tool-name">${escHtml(tool)}</span>
          ${server ? `<span class="trace-server-tag">${escHtml(server)}</span>` : ''}
          <span class="trace-status-${ok ? 'ok' : 'err'}">${ok ? '✓' : '✕'}</span>
          ${dur ? `<span class="trace-duration">${escHtml(dur)}</span>` : ''}
        </div>
        ${args ? `<div class="trace-args">${escHtml(typeof args === 'object' ? JSON.stringify(args, null, 2) : String(args))}</div>` : ''}
      </div>`;

    container.appendChild(el);
  });
}

// ═══════════════════════════════════════════════════════════
// Navigation
// ═══════════════════════════════════════════════════════════

function showSection(sectionId) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const section = document.getElementById(`section-${sectionId}`);
  if (section) section.classList.add('active');

  const navItem = document.querySelector(`[data-section="${sectionId}"]`);
  if (navItem) navItem.classList.add('active');

  // Mobile: close sidebar
  document.getElementById('sidebar')?.classList.remove('mobile-open');
  document.getElementById('sidebar-overlay')?.classList.remove('active');
}

// ═══════════════════════════════════════════════════════════
// UI helpers
// ═══════════════════════════════════════════════════════════

function showError(message) {
  showBanner(message, 'error');
}

function showLoading(show) {
  const overlay = document.getElementById('global-loading');
  if (!overlay) return;
  overlay.style.display = show ? 'flex' : 'none';
}

function showBanner(msg, type = 'info') {
  const container = document.getElementById('alert-container');
  if (!container) return;

  const icons = { info: 'ℹ️', warn: '⚠️', error: '🚨', success: '✅' };
  const id = `banner-${Date.now()}`;

  const el = document.createElement('div');
  el.className = `alert-banner ${type}`;
  el.id = id;
  el.innerHTML = `
    <span class="alert-icon">${icons[type] ?? 'ℹ️'}</span>
    <span class="alert-text">${escHtml(msg)}</span>
    <span class="alert-close" onclick="document.getElementById('${id}')?.remove()">✕</span>`;

  container.appendChild(el);

  // Click anywhere to dismiss
  el.addEventListener('click', () => el.remove());

  // Auto-dismiss after 8 s
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.3s';
    setTimeout(() => el.remove(), 350);
  }, 8_000);
}

function formatDuration(ms) {
  if (ms == null) return '';
  if (ms < 1000)  return `${ms}ms`;
  if (ms < 60_000) return `${(ms/1000).toFixed(1)}s`;
  return `${Math.floor(ms/60_000)}m ${Math.round((ms%60_000)/1000)}s`;
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return String(iso); }
}

function severityBadge(label) {
  const s = (label ?? 'UNKNOWN').toUpperCase();
  const cls = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }[s] ?? 'unknown';
  return `<span class="severity-badge ${cls}">${escHtml(s)}</span>`;
}

function emptyState(icon, title, desc = '') {
  return `
    <div class="empty-state">
      <div class="empty-state-icon">${icon}</div>
      <div class="empty-state-title">${escHtml(title)}</div>
      ${desc ? `<div class="empty-state-desc">${escHtml(desc)}</div>` : ''}
    </div>`;
}

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clearScanUI() {
  const header = document.getElementById('scan-result-header');
  if (header) header.classList.add('hidden');

  const grid = document.getElementById('stat-grid-overview');
  if (grid) grid.innerHTML = '';

  ['vuln-table-scan', 'vuln-table-vulns'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });

  const ghCards = document.getElementById('github-cards');
  if (ghCards) ghCards.innerHTML = '';
}

function setProgressStep(stepId, state_) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = `progress-step ${state_}`;
  const icon = el.querySelector('.progress-step-icon');
  if (!icon) return;
  if (state_ === 'done')   icon.textContent = '✓';
  else if (state_ === 'active') icon.textContent = '⟳';
  else if (state_ === 'error')  icon.textContent = '✕';
  else icon.textContent = '○';
}

function updateNavBadge(navId, count) {
  const item = document.getElementById(navId);
  if (!item) return;
  let badge = item.querySelector('.nav-badge');
  if (count == null || count === 0) {
    badge?.remove();
    item.dataset.count = '0';
    return;
  }
  if (!badge) {
    badge = document.createElement('span');
    badge.className = 'nav-badge';
    item.appendChild(badge);
  }
  badge.textContent = count > 99 ? '99+' : String(count);
  item.dataset.count = String(count);
}

// ═══════════════════════════════════════════════════════════
// Event listeners
// ═══════════════════════════════════════════════════════════

function setupEventListeners() {
  // ── Repo scan form
  const scanForm = document.getElementById('scan-form');
  scanForm?.addEventListener('submit', async e => {
    e.preventDefault();
    const input = document.getElementById('repo-input');
    const val   = (input?.value ?? '').trim();
    if (!val) { showBanner('Please enter a repository (e.g. psf/requests)', 'warn'); return; }

    const parts = val.replace('https://github.com/', '').split('/').filter(Boolean);
    if (parts.length < 2) { showBanner('Format must be owner/repository', 'warn'); return; }

    const [owner, repo] = parts;
    await scanRepo(owner, repo);
  });

  // ── Chat form
  const chatForm = document.getElementById('chat-form');
  chatForm?.addEventListener('submit', async e => {
    e.preventDefault();
    const input = document.getElementById('chat-input');
    const msg   = (input?.value ?? '').trim();
    if (!msg) return;
    input.value = '';
    input.style.height = '';
    const ctx = state.chatContext ?? {};
    await sendChatMessage(msg, ctx.owner ?? null, ctx.repo ?? null);
  });

  // Auto-resize chat textarea
  const chatInput = document.getElementById('chat-input');
  chatInput?.addEventListener('input', () => {
    chatInput.style.height = '';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
  });
  chatInput?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      document.getElementById('chat-form')?.requestSubmit();
    }
  });

  // ── Refresh MCP button
  document.getElementById('btn-refresh-tools')?.addEventListener('click', refreshMCPTools);

  // ── Commit Security Lookup form
  const commitForm = document.getElementById('commit-form');
  commitForm?.addEventListener('submit', async e => {
    e.preventDefault();
    const repoVal = (document.getElementById('commit-repo-input')?.value ?? '').trim();
    const shaVal  = (document.getElementById('commit-sha-input')?.value ?? '').trim();
    let owner = null, repo = null;
    if (repoVal) {
      const parts = repoVal.replace('https://github.com/', '').split('/').filter(Boolean);
      if (parts.length >= 2) {
        owner = parts[0];
        repo  = parts[1];
      } else {
        showBanner('Repository context must be owner/repository', 'warn');
        return;
      }
    }
    if (!shaVal && (!owner || !repo)) {
      showBanner('Enter either owner/repository or a full 40/64-char commit SHA', 'warn');
      return;
    }
    await checkCommit(owner, repo, shaVal || null);
  });

  // ── Sidebar nav
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.addEventListener('click', () => showSection(item.dataset.section));
  });

  // ── Mobile menu
  document.getElementById('mobile-menu-btn')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('mobile-open');
    document.getElementById('sidebar-overlay')?.classList.toggle('active');
  });

  document.getElementById('sidebar-overlay')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.remove('mobile-open');
    document.getElementById('sidebar-overlay')?.classList.remove('active');
  });

  // ── Vuln table sortable headers (delegated)
  document.addEventListener('click', e => {
    const th = e.target.closest('th.sortable');
    if (!th) return;
    const table = th.closest('table');
    if (!table) return;

    const col      = th.dataset.col;
    const isAsc    = th.classList.contains('sort-asc');
    const newDir   = isAsc ? 'desc' : 'asc';

    table.querySelectorAll('th.sortable').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
    th.classList.add(newDir === 'asc' ? 'sort-asc' : 'sort-desc');

    const tbody = table.querySelector('tbody');
    if (!tbody) return;
    const rows  = Array.from(tbody.querySelectorAll('tr'));
    const colIdx = Array.from(th.parentElement.children).indexOf(th);

    rows.sort((a, b) => {
      const av = a.children[colIdx]?.textContent.trim() ?? '';
      const bv = b.children[colIdx]?.textContent.trim() ?? '';
      return newDir === 'asc' ? av.localeCompare(bv) : bv.localeCompare(av);
    });

    rows.forEach(r => tbody.appendChild(r));
  });

  // ── Keyboard shortcut: Ctrl+K → focus repo input
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      showSection('scan');
      document.getElementById('repo-input')?.focus();
    }
  });
}

/** POST /api/commit-check – check latest or exact commit SHA against OSV via MCP */
async function checkCommit(owner, repo, commit) {
  const container = document.getElementById('commit-result-container');
  const btn = document.getElementById('btn-check-commit');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Checking…'; }
  if (container) {
    container.innerHTML = `<div class="inline-loader" style="padding:24px;"><div class="loading-spinner"></div>Querying GitHub & OSV MCP servers…</div>`;
  }

  try {
    const payload = {};
    if (owner) payload.owner = owner;
    if (repo) payload.repo = repo;
    if (commit) payload.commit = commit;

    const data = await apiFetch('/api/commit-check', {
      method: 'POST',
      body: JSON.stringify(payload),
    });

    const trace = data.execution_trace ?? data.trace ?? [];
    if (trace.length) {
      appendTraceItems(trace);
      updateNavBadge('nav-trace', (parseInt(document.getElementById('nav-trace')?.dataset.count ?? '0', 10) + trace.length) || null);
    }

    renderCommitResult(data);
  } catch (err) {
    if (container) {
      container.innerHTML = emptyState('⚠️', 'Commit lookup failed', err.message);
    }
    showError(err.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🔎 Check Commit'; }
  }
}

function renderCommitResult(data) {
  const container = document.getElementById('commit-result-container');
  if (!container) return;

  const vulns = data.vulnerabilities ?? [];
  const commitUrl = data.commit_url
    ? `<a href="${escHtml(data.commit_url)}" target="_blank" rel="noopener"><code>${escHtml(data.commit_hash)}</code> ↗</a>`
    : `<code>${escHtml(data.commit_hash)}</code>`;

  const metaHtml = `
    <div style="padding:12px 16px;border-bottom:1px solid var(--border-muted);display:flex;flex-wrap:wrap;gap:12px;align-items:center;">
      <div><strong>Commit:</strong> ${commitUrl}</div>
      ${data.commit_message ? `<div><strong>Message:</strong> ${escHtml(data.commit_message)}</div>` : ''}
      ${data.author ? `<div><strong>Author:</strong> ${escHtml(data.author)}</div>` : ''}
      <span class="tag">${data.vulnerability_count ?? vulns.length} OSV match(es)</span>
      <span class="tag">${escHtml(data.data_freshness || 'live')}</span>
      <a class="tag" href="${escHtml(data.source_url)}" target="_blank" rel="noopener">OSV API ↗</a>
    </div>`;

  if (!vulns.length) {
    container.innerHTML = metaHtml + emptyState(
      '🛡️',
      'No OSV vulnerability records associated with this commit',
      data.note || 'OSV returned zero matching records. This does not establish that the repository is secure or replace dependency-version scanning.'
    );
    return;
  }

  const rows = vulns.map(v => {
    const fixed = (v.fixed_versions ?? []).join(', ') || '—';
    const pkgs  = (v.affected_packages ?? []).join(', ') || '—';
    const refs  = (v.references ?? []).slice(0, 2).map(r => `<a href="${escHtml(r.url)}" target="_blank" rel="noopener">${escHtml(r.type || 'Ref')} ↗</a>`).join(' ');
    return `
      <tr>
        <td class="cell-package">${escHtml(pkgs)}</td>
        <td class="cell-id"><a href="${escHtml(v.osv_url || buildVulnLink({ id: v.vulnerability_id }))}" target="_blank" rel="noopener">${escHtml(v.vulnerability_id)}</a></td>
        <td>${severityBadge(v.severity_label || 'UNSPECIFIED')}</td>
        <td>${escHtml(v.summary || '—')}</td>
        <td class="cell-fixed">${escHtml(fixed)}</td>
        <td>${refs || '—'}</td>
      </tr>`;
  }).join('');

  container.innerHTML = metaHtml + `
    <div class="table-wrapper">
      <table class="vuln-table">
        <thead>
          <tr>
            <th>Affected Package(s)</th>
            <th>Vulnerability ID</th>
            <th>Severity</th>
            <th>Summary</th>
            <th>Fixed Versions</th>
            <th>References</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ═══════════════════════════════════════════════════════════
// Bootstrap
// ═══════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', init);
