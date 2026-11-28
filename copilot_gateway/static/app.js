/**
 * RepoSentinel AI — Enterprise Security Platform
 * Moole-Inspired Layout & Interactions (Vanilla ES2022)
 */

'use strict';

// ── Global Application State ────────────────────────────────
const state = {
  currentUser: null,
  activeView: 'dashboard',
  projects: [],
  selectedProjectId: 'all',
  dashboardData: null,
  currentScan: null,
  mcpTools: [],
  history: [],
  liveState: null,
  isRailExpanded: false,
};

// ── Entry Point ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  setupHashRouting();

  // Load user session first
  await checkAuthSession();

  // Load platform data in parallel
  await Promise.allSettled([
    loadDashboardOverview(),
    loadProjects(),
    loadLiveState(),
    loadMCPTools(),
    loadScanHistory(),
  ]);

  // Periodic health polling (every 20s)
  setInterval(loadLiveState, 20_000);
});

// ════════════════════════════════════════════════════════════
// API Client Helper
// ════════════════════════════════════════════════════════════

async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers ?? {}) },
    ...options,
  });

  if (!res.ok) {
    let msg = `Request failed (HTTP ${res.status})`;
    try {
      const data = await res.json();
      const raw = data.detail ?? data.error ?? data.message;
      if (typeof raw === 'string') msg = raw;
      else if (raw && typeof raw === 'object') msg = raw.error ?? raw.message ?? JSON.stringify(raw);
    } catch {}
    throw new Error(msg);
  }

  // Handle empty 204 or non-JSON
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return res.json();
  }
  return res.text();
}

// ════════════════════════════════════════════════════════════
// Navigation & View Routing
// ════════════════════════════════════════════════════════════

function setupEventListeners() {
  // Rail toggle
  document.getElementById('rail-toggle-btn')?.addEventListener('click', toggleRail);

  // Rail item clicks
  document.querySelectorAll('.rail-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.dataset.view;
      if (view) switchView(view);
    });
  });

  // Header Brand click -> Home or Dashboard
  document.getElementById('brand-home-link')?.addEventListener('click', () => {
    switchView(state.currentUser ? 'home' : 'landing');
  });

  // Breadcrumbs click
  document.getElementById('bc-home-link')?.addEventListener('click', () => switchView('home'));
  document.getElementById('bc-proj-link')?.addEventListener('click', () => switchView('projects'));

  // Project context dropdown toggle
  const projectPill = document.getElementById('project-pill-btn');
  const projectDropdown = document.getElementById('project-dropdown-menu');
  projectPill?.addEventListener('click', (e) => {
    e.stopPropagation();
    const isShown = projectDropdown.style.display !== 'none';
    projectDropdown.style.display = isShown ? 'none' : 'block';
  });
  document.addEventListener('click', () => {
    if (projectDropdown) projectDropdown.style.display = 'none';
    const userMenu = document.getElementById('user-dropdown-menu');
    if (userMenu) userMenu.style.display = 'none';
  });

  // Header Add Project button
  document.getElementById('btn-header-add-project')?.addEventListener('click', () => openProjectModal());
  document.getElementById('btn-dash-add-repo')?.addEventListener('click', () => openProjectModal());
  document.getElementById('btn-home-add-project')?.addEventListener('click', () => openProjectModal());
  document.getElementById('btn-projects-add-modal')?.addEventListener('click', () => openProjectModal());
  document.getElementById('btn-empty-add-project')?.addEventListener('click', () => openProjectModal());

  // User avatar menu toggle
  const avatarBtn = document.getElementById('user-avatar-btn');
  const userMenu = document.getElementById('user-dropdown-menu');
  avatarBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    const isShown = userMenu.style.display !== 'none';
    userMenu.style.display = isShown ? 'none' : 'block';
  });

  // Auth buttons
  document.getElementById('btn-nav-login')?.addEventListener('click', () => openAuthModal('login'));
  document.getElementById('btn-nav-register')?.addEventListener('click', () => openAuthModal('register'));
  document.getElementById('btn-landing-get-started')?.addEventListener('click', () => {
    if (state.currentUser) switchView('dashboard');
    else openAuthModal('register');
  });
  document.getElementById('btn-landing-demo')?.addEventListener('click', () => switchView('dashboard'));
  document.getElementById('btn-landing-to-mcp')?.addEventListener('click', () => switchView('mcp'));
  document.getElementById('btn-home-to-dashboard')?.addEventListener('click', () => switchView('dashboard'));
  document.getElementById('btn-home-all-projects')?.addEventListener('click', () => switchView('projects'));
  document.getElementById('btn-home-all-scans')?.addEventListener('click', () => switchView('activity'));

  // User menu items
  document.getElementById('menu-item-home')?.addEventListener('click', () => switchView('home'));
  document.getElementById('menu-item-projects')?.addEventListener('click', () => switchView('projects'));
  document.getElementById('menu-item-settings')?.addEventListener('click', () => switchView('settings'));
  document.getElementById('menu-item-logout')?.addEventListener('click', handleLogout);
  document.getElementById('btn-settings-logout')?.addEventListener('click', handleLogout);

  // Modals close
  document.getElementById('modal-auth-close')?.addEventListener('click', () => closeAuthModal());
  document.getElementById('modal-project-close')?.addEventListener('click', () => closeProjectModal());
  document.getElementById('btn-cancel-project')?.addEventListener('click', () => closeProjectModal());

  // Auth form submissions
  document.getElementById('tab-login-btn')?.addEventListener('click', () => switchAuthTab('login'));
  document.getElementById('tab-register-btn')?.addEventListener('click', () => switchAuthTab('register'));
  document.getElementById('form-login')?.addEventListener('submit', handleLogin);
  document.getElementById('form-register')?.addEventListener('submit', handleRegister);
  document.getElementById('form-add-project')?.addEventListener('submit', handleAddProject);

  // Quick scan on Home page
  document.getElementById('btn-home-scan-run')?.addEventListener('click', () => {
    const input = document.getElementById('home-scan-input')?.value.trim();
    if (input) triggerScan(input);
  });

  // Dashboard Repository Search
  document.getElementById('dash-repo-search')?.addEventListener('input', (e) => {
    filterDashboardTable(e.target.value);
  });

  // Vulnerability filter
  document.getElementById('vuln-search-input')?.addEventListener('input', (e) => {
    filterVulnsTable(e.target.value);
  });

  // Commit Check
  document.getElementById('btn-run-commit-check')?.addEventListener('click', handleCommitCheck);

  // Copilot Chat
  document.getElementById('btn-copilot-send')?.addEventListener('click', handleCopilotSend);
  document.getElementById('copilot-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleCopilotSend();
    }
  });
  document.getElementById('btn-clear-chat')?.addEventListener('click', clearCopilotChat);

  // MCP Refresh
  document.getElementById('btn-mcp-refresh')?.addEventListener('click', refreshMCPTools);

  // Global search keyboard shortcut (Ctrl+K)
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      document.getElementById('global-search-input')?.focus();
    }
  });
}

function toggleRail() {
  state.isRailExpanded = !state.isRailExpanded;
  const rail = document.getElementById('nav-rail');
  rail?.classList.toggle('expanded', state.isRailExpanded);
}

function switchView(viewName) {
  state.activeView = viewName;

  // Update URL hash
  window.location.hash = `#${viewName}`;

  // Update Rail active class
  document.querySelectorAll('.rail-item').forEach(item => {
    item.classList.toggle('active', item.dataset.view === viewName);
  });

  // Show only target view
  document.querySelectorAll('.page-view').forEach(view => {
    view.style.display = view.id === `view-${viewName}` ? 'block' : 'none';
  });

  // Trigger view-specific re-renders
  if (viewName === 'dashboard') loadDashboardOverview();
  if (viewName === 'projects') renderProjectsList();
  if (viewName === 'activity') renderActivityTable();
  if (viewName === 'settings') renderSettings();
  if (viewName === 'vulnerabilities' && state.currentScan) renderVulnerabilitiesTable(state.currentScan);
}

function setupHashRouting() {
  const hash = window.location.hash.replace('#', '').trim();
  if (hash) {
    switchView(hash);
  } else {
    // Default to dashboard
    switchView('dashboard');
  }

  window.addEventListener('hashchange', () => {
    const newHash = window.location.hash.replace('#', '').trim();
    if (newHash && newHash !== state.activeView) {
      switchView(newHash);
    }
  });
}

// ════════════════════════════════════════════════════════════
// Authentication & User Session
// ════════════════════════════════════════════════════════════

async function checkAuthSession() {
  try {
    const user = await apiFetch('/api/auth/me');
    state.currentUser = user;
    renderAuthUI(user);
  } catch {
    state.currentUser = null;
    renderAuthUI(null);
  }
}

function renderAuthUI(user) {
  const unauthControls = document.getElementById('unauth-controls');
  const authControls = document.getElementById('auth-controls');

  if (user) {
    unauthControls.style.display = 'none';
    authControls.style.display = 'flex';

    const initials = (user.full_name || user.username || 'RS')
      .split(' ')
      .map(w => w[0])
      .join('')
      .substring(0, 2)
      .toUpperCase();

    document.getElementById('user-avatar-initials').textContent = initials;
    document.getElementById('menu-user-name').textContent = user.full_name || user.username;
    document.getElementById('menu-user-email').textContent = user.email;
    document.getElementById('home-welcome-name').textContent = `Welcome back, ${user.full_name || user.username}`;
  } else {
    unauthControls.style.display = 'flex';
    authControls.style.display = 'none';
  }
}

function openAuthModal(tab = 'login') {
  const modal = document.getElementById('auth-modal');
  modal.style.display = 'flex';
  switchAuthTab(tab);
}

function closeAuthModal() {
  document.getElementById('auth-modal').style.display = 'none';
}

function switchAuthTab(tab) {
  const isLogin = tab === 'login';
  document.getElementById('tab-login-btn').classList.toggle('active', isLogin);
  document.getElementById('tab-register-btn').classList.toggle('active', !isLogin);
  document.getElementById('form-login').style.display = isLogin ? 'block' : 'none';
  document.getElementById('form-register').style.display = isLogin ? 'none' : 'block';
  document.getElementById('login-error-msg').style.display = 'none';
  document.getElementById('reg-error-msg').style.display = 'none';
}

async function handleLogin(e) {
  e.preventDefault();
  const idInput = document.getElementById('login-id').value.trim();
  const pwdInput = document.getElementById('login-pwd').value;
  const errorEl = document.getElementById('login-error-msg');
  errorEl.style.display = 'none';

  try {
    const user = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username_or_email: idInput, password: pwdInput }),
    });
    state.currentUser = user;
    renderAuthUI(user);
    closeAuthModal();
    showAlert(`Welcome back, ${user.username}!`, 'success');
    await loadProjects();
    await loadDashboardOverview();
    switchView('dashboard');
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = 'block';
  }
}

async function handleRegister(e) {
  e.preventDefault();
  const fullName = document.getElementById('reg-name').value.trim();
  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-pwd').value;
  const errorEl = document.getElementById('reg-error-msg');
  errorEl.style.display = 'none';

  try {
    const user = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        full_name: fullName || null,
        username,
        email,
        password,
      }),
    });
    state.currentUser = user;
    renderAuthUI(user);
    closeAuthModal();
    showAlert(`Account created successfully! Welcome to RepoSentinel AI.`, 'success');
    await loadProjects();
    await loadDashboardOverview();
    switchView('home');
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = 'block';
  }
}

async function handleLogout() {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch {}
  state.currentUser = null;
  renderAuthUI(null);
  showAlert('You have been signed out.', 'info');
  switchView('landing');
}

// ════════════════════════════════════════════════════════════
// Projects Management
// ════════════════════════════════════════════════════════════

async function loadProjects() {
  if (!state.currentUser) return;
  try {
    const data = await apiFetch('/api/projects');
    state.projects = data?.projects ?? [];
    renderProjectDropdown();
    renderProjectsList();
  } catch {
    state.projects = [];
  }
}

function openProjectModal() {
  if (!state.currentUser) {
    showAlert('Please sign in or create an account to onboard repositories.', 'info');
    openAuthModal('login');
    return;
  }
  document.getElementById('add-project-modal').style.display = 'flex';
  document.getElementById('project-error-msg').style.display = 'none';
  document.getElementById('project-repo-input').value = '';
}

function closeProjectModal() {
  document.getElementById('add-project-modal').style.display = 'none';
}

async function handleAddProject(e) {
  e.preventDefault();
  const repoSlug = document.getElementById('project-repo-input').value.trim();
  const errorEl = document.getElementById('project-error-msg');
  errorEl.style.display = 'none';

  try {
    showLoading(true, 'Verifying repository via GitHub REST API...');
    const project = await apiFetch('/api/projects', {
      method: 'POST',
      body: JSON.stringify({ repo_url_or_slug: repoSlug }),
    });
    closeProjectModal();
    showAlert(`Repository ${project.owner}/${project.repo} onboarded successfully!`, 'success');
    await loadProjects();
    await loadDashboardOverview();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.style.display = 'block';
  } finally {
    showLoading(false);
  }
}

async function deleteProject(projectId, owner, repo) {
  if (!confirm(`Are you sure you want to remove ${owner}/${repo} from onboarded projects?`)) return;
  try {
    await apiFetch(`/api/projects/${projectId}`, { method: 'DELETE' });
    showAlert(`Removed ${owner}/${repo}.`, 'info');
    await loadProjects();
    await loadDashboardOverview();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

function renderProjectDropdown() {
  const listEl = document.getElementById('project-dropdown-list');
  if (!listEl) return;

  let html = `
    <div class="dropdown-item ${state.selectedProjectId === 'all' ? 'active' : ''}" data-project-id="all">
      <span class="item-badge">ALL</span>
      <span class="item-name">All Repositories</span>
    </div>
  `;

  for (const p of state.projects) {
    const isAct = state.selectedProjectId === String(p.id);
    const initial = p.repo.charAt(0).toUpperCase();
    html += `
      <div class="dropdown-item ${isAct ? 'active' : ''}" data-project-id="${p.id}" data-owner="${p.owner}" data-repo="${p.repo}">
        <span class="item-badge">${initial}</span>
        <span class="item-name">${p.owner}/${p.repo}</span>
      </div>
    `;
  }
  listEl.innerHTML = html;

  listEl.querySelectorAll('.dropdown-item').forEach(item => {
    item.addEventListener('click', () => {
      state.selectedProjectId = item.dataset.projectId;
      const name = item.querySelector('.item-name')?.textContent || 'All Repositories';
      const badge = item.querySelector('.item-badge')?.textContent || 'ALL';
      document.getElementById('project-pill-name').textContent = name;
      document.getElementById('project-pill-badge').textContent = badge;
      document.getElementById('project-dropdown-menu').style.display = 'none';
      loadDashboardOverview();
    });
  });
}

function renderProjectsList() {
  const container = document.getElementById('projects-grid-container');
  if (!container) return;

  if (state.projects.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No Projects Onboarded</h3>
        <p>Add your first repository to automatically track vulnerabilities and remediation pull requests.</p>
        <button class="btn btn-primary mt-3" onclick="openProjectModal()">+ Add Repository</button>
      </div>
    `;
    return;
  }

  let html = '';
  for (const p of state.projects) {
    html += `
      <div class="card p-4">
        <div class="card-header-row mb-2">
          <h4>${escapeHtml(p.owner)}/<span class="text-white">${escapeHtml(p.repo)}</span></h4>
          <span class="status-badge ok">GitHub</span>
        </div>
        <p class="text-sm text-muted mb-3">${escapeHtml(p.description || 'No description provided on GitHub.')}</p>
        <div class="project-stats-row text-xs text-muted mb-4">
          <span>Branch: <code>${escapeHtml(p.default_branch)}</code></span> · 
          <span>★ ${p.stars}</span> · 
          <span>Forks: ${p.forks}</span> · 
          <span>Manifest: <code>${escapeHtml(p.primary_manifest || 'Auto-detect')}</code></span>
        </div>
        <div class="project-actions-row flex gap-2">
          <button class="btn btn-sm btn-primary" onclick="triggerScan('${escapeHtml(p.owner)}/${escapeHtml(p.repo)}')">Run Security Scan</button>
          <button class="btn btn-sm btn-outline text-danger" onclick="deleteProject(${p.id}, '${escapeHtml(p.owner)}', '${escapeHtml(p.repo)}')">Remove</button>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

// ════════════════════════════════════════════════════════════
// THE MOOLE DASHBOARD (Severity Cards + Donut Chart + Table)
// ════════════════════════════════════════════════════════════

async function loadDashboardOverview() {
  try {
    const data = await apiFetch('/api/dashboard/overview');
    state.dashboardData = data;
    renderMooleDashboard(data);
  } catch (err) {
    console.error('Failed to load dashboard overview:', err);
  }
}

function renderMooleDashboard(data) {
  if (!data) return;

  // 1. Breadcrumb onboarded pill
  const count = data.total_onboarded_repositories ?? 0;
  document.getElementById('dashboard-onboarded-text').textContent = `Total onboarded repositories: ${count}`;

  // 2. Four Severity Cards
  document.getElementById('dash-crit-count').textContent = `Total: ${data.critical_total ?? 0}`;
  document.getElementById('dash-high-count').textContent = `Total: ${data.high_total ?? 0}`;
  document.getElementById('dash-med-count').textContent = `Total: ${data.medium_total ?? 0}`;
  document.getElementById('dash-low-count').textContent = `Total: ${data.low_total ?? 0}`;

  // 3. Donut Chart SVG
  renderDonutChart(data);

  // 4. Repositories Table
  renderDashboardTable(data.repositories || []);
}

function renderDonutChart(data) {
  const total = (data.critical_total || 0) + (data.high_total || 0) + (data.medium_total || 0) + (data.low_total || 0);
  document.getElementById('donut-total-vulns').textContent = total;

  const svg = document.getElementById('donut-svg');
  if (!svg) return;

  if (total === 0) {
    svg.innerHTML = `
      <circle class="donut-ring" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#1e293b" stroke-width="6"></circle>
    `;
    return;
  }

  const critPct = (data.critical_total / total) * 100;
  const highPct = (data.high_total / total) * 100;
  const medPct  = (data.medium_total / total) * 100;
  const lowPct  = (data.low_total / total) * 100;

  let offset = 25; // start at 12 o'clock

  function createSlice(pct, color) {
    if (pct <= 0) return '';
    const sliceHtml = `
      <circle class="donut-segment" cx="21" cy="21" r="15.91549430918954"
        fill="transparent" stroke="${color}" stroke-width="6"
        stroke-dasharray="${pct} ${100 - pct}"
        stroke-dashoffset="${offset}">
      </circle>
    `;
    offset -= pct;
    return sliceHtml;
  }

  let html = `<circle class="donut-ring" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#1e293b" stroke-width="6"></circle>`;
  html += createSlice(critPct, 'var(--sev-critical)');
  html += createSlice(highPct, 'var(--sev-high)');
  html += createSlice(medPct,  'var(--sev-medium)');
  html += createSlice(lowPct,  'var(--sev-low)');

  svg.innerHTML = html;
}

function renderDashboardTable(repos) {
  const tbody = document.getElementById('dashboard-repos-tbody');
  if (!tbody) return;

  if (repos.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" class="text-center py-4 text-muted">
          No repositories onboarded yet. Click "+ Add Repository" to begin auditing codebases.
        </td>
      </tr>
    `;
    return;
  }

  let html = '';
  for (const r of repos) {
    const lastScanFormatted = r.last_scan
      ? new Date(r.last_scan).toLocaleString()
      : 'Never scanned';

    html += `
      <tr data-repo-name="${escapeHtml(r.repository)}">
        <td>
          <strong>${escapeHtml(r.repository)}</strong>
        </td>
        <td class="text-center text-critical">${r.critical}</td>
        <td class="text-center text-high">${r.high}</td>
        <td class="text-center text-medium">${r.medium}</td>
        <td class="text-center text-low">${r.low}</td>
        <td><code>${escapeHtml(r.build_file || 'requirements.txt')}</code></td>
        <td>
          <span style="display:inline-flex;align-items:center;gap:6px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            GitHub
          </span>
        </td>
        <td class="text-muted text-xs">${escapeHtml(lastScanFormatted)}</td>
        <td class="text-right">
          <button class="btn btn-xs btn-primary" onclick="triggerScan('${escapeHtml(r.repository)}')">Scan</button>
        </td>
      </tr>
    `;
  }
  tbody.innerHTML = html;
}

function filterDashboardTable(query) {
  const q = query.toLowerCase();
  const rows = document.querySelectorAll('#dashboard-repos-tbody tr');
  rows.forEach(r => {
    const name = r.dataset.repoName || '';
    r.style.display = name.toLowerCase().includes(q) ? '' : 'none';
  });
}

// ════════════════════════════════════════════════════════════
// Scanning & Findings
// ════════════════════════════════════════════════════════════

async function triggerScan(repoInput) {
  let [owner, repo] = repoInput.replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').split('/');
  if (!owner || !repo) {
    showAlert("Please specify a valid repository as 'owner/repo'.", 'warn');
    return;
  }
  owner = owner.trim();
  repo = repo.trim();

  showLoading(true, `Auditing dependencies and vulnerabilities for ${owner}/${repo}...`);

  try {
    const scanResult = await apiFetch('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ owner, repo }),
    });

    state.currentScan = scanResult;

    // Update nav badge
    const vulnCount = scanResult.total_vulnerabilities ?? 0;
    const badge = document.getElementById('badge-vulns');
    if (badge) {
      badge.textContent = vulnCount;
      badge.style.display = vulnCount > 0 ? 'inline-block' : 'none';
    }

    // Refresh dashboard and history
    await loadDashboardOverview();
    await loadScanHistory();

    // Render findings
    renderVulnerabilitiesTable(scanResult);
    renderGithubCorrelation(scanResult);

    showAlert(`Scan complete for ${owner}/${repo} — ${vulnCount} vulnerabilities identified.`, 'success');
    switchView('vulnerabilities');
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    showLoading(false);
  }
}

function renderVulnerabilitiesTable(scan) {
  const tbody = document.getElementById('vulns-findings-tbody');
  if (!tbody) return;

  const vulns = scan.vulnerabilities || [];
  if (vulns.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center py-4 text-muted">
          No vulnerabilities found for ${escapeHtml(scan.owner)}/${escapeHtml(scan.repo)}.
        </td>
      </tr>
    `;
    return;
  }

  let html = '';
  for (const pkg of vulns) {
    const pkgName = pkg.package_name || pkg.package || 'Unknown';
    const installedVer = pkg.installed_version || pkg.version || 'Pinned';
    const subVulns = pkg.vulnerabilities || [pkg];

    for (const v of subVulns) {
      const vid = v.vulnerability_id || v.id || 'N/A';
      const sev = (v.severity_label || v.severity || 'UNKNOWN').toUpperCase();
      let sevClass = 'text-low';
      if (sev.includes('CRIT')) sevClass = 'text-critical';
      else if (sev.includes('HIGH')) sevClass = 'text-high';
      else if (sev.includes('MED') || sev.includes('MOD')) sevClass = 'text-medium';

      const fixedVersions = (v.fixed_versions || []).join(', ') || 'None';
      const ranges = (v.affected_ranges || []).join('; ') || 'N/A';
      const osvUrl = v.osv_url || `https://osv.dev/vulnerability/${vid}`;

      html += `
        <tr>
          <td><strong>${escapeHtml(pkgName)}</strong></td>
          <td><code>${escapeHtml(installedVer)}</code></td>
          <td><a href="${escapeHtml(osvUrl)}" target="_blank" rel="noopener">${escapeHtml(vid)}</a></td>
          <td><span class="${sevClass}">${escapeHtml(sev)}</span></td>
          <td class="text-xs text-muted">${escapeHtml(ranges)}</td>
          <td><code>${escapeHtml(fixedVersions)}</code></td>
          <td><span class="text-xs text-muted">OSV.dev</span></td>
        </tr>
      `;
    }
  }
  tbody.innerHTML = html;
}

function filterVulnsTable(query) {
  const q = query.toLowerCase();
  const rows = document.querySelectorAll('#vulns-findings-tbody tr');
  rows.forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function renderGithubCorrelation(scan) {
  const container = document.getElementById('github-correlation-grid');
  if (!container) return;

  const gh = scan.github || {};
  const issues = gh.issues || [];
  const prs = gh.pull_requests || gh.pulls || [];

  if (issues.length === 0 && prs.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No Issues or Pull Requests Found</h3>
        <p>No open issues or remediation pull requests reported by GitHub for ${escapeHtml(scan.owner)}/${escapeHtml(scan.repo)}.</p>
      </div>
    `;
    return;
  }

  let html = '';
  // Remediation PRs
  for (const pr of prs) {
    const isConfirmed = pr.confirmed_match;
    html += `
      <div class="card p-3">
        <div class="card-header-row mb-1">
          <span class="status-badge ${isConfirmed ? 'ok' : 'warn'}">
            ${isConfirmed ? 'CONFIRMED REMEDIATION PR' : 'PULL REQUEST'}
          </span>
          <span class="text-xs text-muted">#${pr.number}</span>
        </div>
        <h4 class="text-sm font-semibold mb-2">
          <a href="${escapeHtml(pr.html_url)}" target="_blank" rel="noopener">${escapeHtml(pr.title)}</a>
        </h4>
        <p class="text-xs text-muted">Author: @${escapeHtml(pr.user?.login || pr.author || 'unknown')}</p>
      </div>
    `;
  }
  // Issues
  for (const issue of issues) {
    html += `
      <div class="card p-3">
        <div class="card-header-row mb-1">
          <span class="status-badge">ISSUE</span>
          <span class="text-xs text-muted">#${issue.number}</span>
        </div>
        <h4 class="text-sm font-semibold mb-2">
          <a href="${escapeHtml(issue.html_url)}" target="_blank" rel="noopener">${escapeHtml(issue.title)}</a>
        </h4>
        <p class="text-xs text-muted">Author: @${escapeHtml(issue.user?.login || issue.author || 'unknown')}</p>
      </div>
    `;
  }
  container.innerHTML = html;
}

// ════════════════════════════════════════════════════════════
// Commit Security Lookup
// ════════════════════════════════════════════════════════════

async function handleCommitCheck() {
  const repo = document.getElementById('commit-repo-input')?.value.trim();
  const sha = document.getElementById('commit-sha-input')?.value.trim();

  let owner = null, rName = null;
  if (repo) {
    const parts = repo.split('/');
    if (parts.length === 2) {
      owner = parts[0].trim();
      rName = parts[1].trim();
    }
  }

  showLoading(true, 'Querying commit hash against OSV vulnerability records...');
  try {
    const res = await apiFetch('/api/commit-check', {
      method: 'POST',
      body: JSON.stringify({ owner, repo: rName, commit: sha || null }),
    });

    const area = document.getElementById('commit-results-area');
    const card = document.getElementById('commit-results-card');
    area.style.display = 'block';

    const vulnsCount = res.vulnerability_count || 0;
    const isVulnerable = vulnsCount > 0;

    let vulnsHtml = '';
    if (isVulnerable) {
      vulnsHtml = `<ul class="mt-2 text-sm">`;
      for (const v of res.vulnerabilities || []) {
        vulnsHtml += `<li><strong>${escapeHtml(v.vulnerability_id || v.id)}</strong>: ${escapeHtml(v.summary || 'Known advisory')}</li>`;
      }
      vulnsHtml += `</ul>`;
    }

    card.innerHTML = `
      <div class="card-header-row mb-3">
        <h3>Commit Audit: <code>${escapeHtml(res.commit_hash)}</code></h3>
        <span class="status-badge ${isVulnerable ? 'err' : 'ok'}">
          ${isVulnerable ? `${vulnsCount} VULNERABILITIES DETECTED` : '0 OSV ADVISORIES LINKED'}
        </span>
      </div>
      <p class="text-sm text-muted mb-2"><strong>Author:</strong> ${escapeHtml(res.author || 'N/A')} · <strong>Source:</strong> <code>${escapeHtml(res.source_url)}</code></p>
      <p class="text-sm text-muted mb-3">${escapeHtml(res.commit_message || '')}</p>
      ${vulnsHtml}
      <div class="text-xs text-muted mt-3 p-2 bg-dark rounded border border-subtle">
        ${escapeHtml(res.note || 'Zero records does not replace full dependency scanning.')}
      </div>
    `;

    showAlert(`Commit query completed: ${vulnsCount} vulnerabilities linked to commit.`, isVulnerable ? 'warn' : 'success');
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    showLoading(false);
  }
}

// ════════════════════════════════════════════════════════════
// AI Security Copilot
// ════════════════════════════════════════════════════════════

async function handleCopilotSend() {
  const input = document.getElementById('copilot-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';

  const container = document.getElementById('copilot-messages-container');
  // Add User bubble
  container.innerHTML += `
    <div class="chat-bubble user">
      <div class="bubble-content">${escapeHtml(text)}</div>
    </div>
  `;
  container.scrollTop = container.scrollHeight;

  // Add Thinking bubble
  const thinkingId = `thinking-${Date.now()}`;
  container.innerHTML += `
    <div class="chat-bubble assistant" id="${thinkingId}">
      <div class="bubble-header">RepoSentinel Copilot</div>
      <div class="bubble-content text-muted">Orchestrating MCP tool calls via Groq and synthesizing security report...</div>
    </div>
  `;
  container.scrollTop = container.scrollHeight;

  try {
    const owner = state.currentScan?.owner || null;
    const repo = state.currentScan?.repo || null;

    const data = await apiFetch('/api/chat', {
      method: 'POST',
      body: JSON.stringify({ message: text, owner, repo }),
    });

    const targetBubble = document.getElementById(thinkingId);
    if (targetBubble) {
      let formattedResponse = escapeHtml(data.response || 'No response produced.');
      formattedResponse = formattedResponse.replace(/\n/g, '<br>');

      targetBubble.innerHTML = `
        <div class="bubble-header">RepoSentinel Copilot · <span class="text-xs text-muted">${escapeHtml(data.groq_model_used || 'Groq')}</span></div>
        <div class="bubble-content">${formattedResponse}</div>
      `;
    }
    container.scrollTop = container.scrollHeight;
  } catch (err) {
    const targetBubble = document.getElementById(thinkingId);
    if (targetBubble) {
      targetBubble.innerHTML = `
        <div class="bubble-header text-danger">Error</div>
        <div class="bubble-content text-danger">${escapeHtml(err.message)}</div>
      `;
    }
  }
}

function clearCopilotChat() {
  const container = document.getElementById('copilot-messages-container');
  if (container) {
    container.innerHTML = `
      <div class="chat-bubble assistant">
        <div class="bubble-header">RepoSentinel Copilot</div>
        <div class="bubble-content">Conversation cleared. What repository or vulnerability shall we investigate next?</div>
      </div>
    `;
  }
}

// ════════════════════════════════════════════════════════════
// MCP Inspector & Live State
// ════════════════════════════════════════════════════════════

async function loadMCPTools() {
  try {
    const data = await apiFetch('/api/mcp-tools');
    state.mcpTools = data.tools || [];
    renderMCPTools();
  } catch (err) {
    console.error('Failed to load MCP tools:', err);
  }
}

async function refreshMCPTools() {
  showLoading(true, 'Rediscovering MCP tools from both Synapse servers...');
  try {
    const data = await apiFetch('/api/refresh-tools', { method: 'POST' });
    state.mcpTools = data.tools || [];
    renderMCPTools();
    showAlert(`Rediscovered ${data.total_tools} MCP tools across both microservices!`, 'success');
  } catch (err) {
    showAlert(err.message, 'error');
  } finally {
    showLoading(false);
  }
}

function renderMCPTools() {
  const container = document.getElementById('mcp-tools-list');
  if (!container) return;

  let html = '';
  for (const t of state.mcpTools) {
    html += `
      <div class="mcp-tool-card">
        <div>
          <div class="tool-header-row">
            <span class="tool-name-code">${escapeHtml(t.tool_name || t.name)}</span>
          </div>
          <p class="tool-desc-text">${escapeHtml(t.description || 'No description provided by Synapse.')}</p>
        </div>
        <span class="tool-server-badge">${escapeHtml(t.server_name || t.server || 'microservice')}</span>
      </div>
    `;
  }
  container.innerHTML = html;
}

async function loadLiveState() {
  try {
    const data = await apiFetch('/api/live-state');
    state.liveState = data;

    const ghDot = document.getElementById('status-gh-dot');
    const osvDot = document.getElementById('status-osv-dot');
    const mcpDot = document.getElementById('status-mcp-dot');

    if (ghDot) ghDot.className = `status-indicator-dot ${data.github_service_status === 'ok' ? 'ok' : 'err'}`;
    if (osvDot) osvDot.className = `status-indicator-dot ${data.osv_service_status === 'ok' ? 'ok' : 'err'}`;
    if (mcpDot) mcpDot.className = `status-indicator-dot ${data.mcp_tools_discovered >= 10 ? 'ok' : 'warn'}`;
  } catch {}
}

async function loadScanHistory() {
  try {
    const data = await apiFetch('/api/history');
    state.history = data || [];
    renderActivityTable();
  } catch {}
}

function renderActivityTable() {
  const tbody = document.getElementById('activity-tbody');
  if (!tbody) return;

  if (state.history.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted">No scan records logged yet.</td></tr>`;
    return;
  }

  let html = '';
  for (const h of state.history) {
    html += `
      <tr>
        <td>#${h.id}</td>
        <td><strong>${escapeHtml(h.owner)}/${escapeHtml(h.repo)}</strong></td>
        <td><span class="status-badge ${h.status === 'completed' ? 'ok' : 'err'}">${escapeHtml(h.status)}</span></td>
        <td>${h.total_dependencies}</td>
        <td>${h.total_vulnerabilities}</td>
        <td class="text-critical">${h.critical || 0}</td>
        <td>${h.duration_seconds || '0'}s</td>
        <td class="text-xs text-muted">${new Date(h.scanned_at || h.started_at).toLocaleString()}</td>
      </tr>
    `;
  }
  tbody.innerHTML = html;
}

function renderSettings() {
  if (!state.currentUser) return;
  document.getElementById('settings-username').value = state.currentUser.username;
  document.getElementById('settings-email').value = state.currentUser.email;
  document.getElementById('settings-created').value = new Date(state.currentUser.created_at).toLocaleString();
}

// ════════════════════════════════════════════════════════════
// Utilities: Alert Banner & Loading
// ════════════════════════════════════════════════════════════

function showAlert(message, type = 'info') {
  const container = document.getElementById('alert-container');
  if (!container) return;

  const alert = document.createElement('div');
  alert.className = `alert-toast ${type}`;
  alert.innerHTML = `
    <span>${escapeHtml(message)}</span>
    <button class="alert-close-btn">&times;</button>
  `;
  alert.querySelector('.alert-close-btn').onclick = () => alert.remove();

  container.appendChild(alert);
  setTimeout(() => alert.remove(), 6000);
}

function showLoading(show, text = 'Processing...') {
  const overlay = document.getElementById('global-loading');
  const label = document.getElementById('global-loading-text');
  if (label) label.textContent = text;
  if (overlay) overlay.style.display = show ? 'flex' : 'none';
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
