// FallBCK Web UI Core JavaScript

// 0. Authenticated API access: same-origin session cookie + CSRF header.
// A 401 means the session expired: send the user back through login.
async function apiFetch(url, options = {}) {
  const headers = Object.assign({ 'X-Requested-With': 'fallbck' }, options.headers || {});
  const resp = await fetch(url, Object.assign({}, options, { headers, credentials: 'same-origin' }));
  if (resp.status === 401) {
    window.location.href = '/auth/login?next=' + encodeURIComponent(window.location.pathname + window.location.search);
    throw new Error('Session expired, redirecting to login');
  }
  return resp;
}

async function logout() {
  try {
    await apiFetch('/auth/logout', { method: 'POST' });
  } finally {
    window.location.href = '/login';
  }
}

// 1. Theme Management (Light / Dark Mode)
(function initTheme() {
  const savedTheme = localStorage.getItem('fallbck_theme') || 
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', savedTheme);
})();

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('fallbck_theme', next);
  updateThemeIcon();
}

function updateThemeIcon() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const sunIcon = document.getElementById('theme-icon-sun');
  const moonIcon = document.getElementById('theme-icon-moon');
  if (sunIcon && moonIcon) {
    if (current === 'dark') {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    } else {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  updateThemeIcon();
});

// 2. Toast Notifications
function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✓';
  if (type === 'error') icon = '✕';
  if (type === 'warning') icon = '⚠';

  toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// 3. Modal Helpers
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('open');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('open');
  }
}

// Close modal when clicking outside
window.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-backdrop')) {
    e.target.classList.remove('open');
  }
});

// 4. Copy to Clipboard
function copyToClipboard(elementIdOrText) {
  let text = elementIdOrText;
  const el = document.getElementById(elementIdOrText);
  if (el) {
    text = el.innerText || el.value;
  }

  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard!', 'success');
  }).catch(err => {
    showToast('Failed to copy', 'error');
  });
}

// 5. Agent Guided Installation Wizard
async function prepareAgentWizard(os = 'linux') {
  const codeEl = document.getElementById('agent-install-cmd');
  const tokenDisplay = document.getElementById('agent-token-val');
  if (!codeEl) return;

  codeEl.innerText = 'Generating single-use enrollment token...';

  try {
    const resp = await apiFetch('/api/v1/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: `Wizard-${os}-${new Date().toISOString().slice(0, 19)}`, max_uses: 1, expires_at: new Date(Date.now() + 24 * 3600 * 1000) })
    });
    
    if (!resp.ok) throw new Error('Token generation failed');
    const data = await resp.json();
    const serverUrl = window.location.origin;

    if (tokenDisplay) tokenDisplay.innerText = data.raw_token;

    if (os === 'linux') {
      codeEl.innerText = `curl -sSL ${serverUrl}/install-agent.sh | sudo bash -s -- \\\n  --server ${serverUrl} \\\n  --token ${data.raw_token}`;
    } else if (os === 'cli') {
      codeEl.innerText = `fallbck-agent enroll \\\n  --server ${serverUrl} \\\n  --token ${data.raw_token}`;
    } else if (os === 'db') {
      codeEl.innerText = `fallbck-db-agent enroll \\\n  --server ${serverUrl} \\\n  --token ${data.raw_token}\n\n# then check the database client tools and start the service:\nfallbck-db-agent tools\nsystemctl enable --now fallbck-db-agent`;
    } else if (os === 'windows') {
      codeEl.innerText = `iwr -useb ${serverUrl}/install-agent.ps1 | iex;\nfallbck-agent.exe enroll --server ${serverUrl} --token ${data.raw_token}`;
    }
  } catch (err) {
    codeEl.innerText = `Error: ${err.message}`;
  }
}

// 6. Action Handlers for Target, Job, and Run Creation
async function submitTargetForm(e) {
  e.preventDefault();
  const form = e.target;
  const formData = new FormData(form);

  const payload = {
    name: formData.get('name'),
    target_type: formData.get('target_type') || 'pbs',
    endpoint: formData.get('endpoint'),
    datastore: formData.get('datastore'),
    namespace: formData.get('namespace') || '',
    auth_token: formData.get('auth_token') || '',
    fingerprint: formData.get('fingerprint') || '',
    tls_verify: formData.get('tls_verify') === 'on',
    pxar_format: formData.get('pxar_format') || 'v1'
  };

  try {
    const resp = await apiFetch('/api/v1/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const errData = await resp.json();
      throw new Error(errData.error || 'Failed to save target');
    }

    showToast('Backup target added successfully!', 'success');
    closeModal('modal-add-target');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Job modal: shared between "create" and "edit" (data-job-id decides)
function jobForm() { return document.getElementById('job-form'); }

// Job type switches the form between the filesystem and database sections and
// limits the agent list to agents of that type
function setJobType(type) {
  const form = jobForm();
  const isDB = type === 'database';
  const fs = document.getElementById('job-fs-fields');
  const dbf = document.getElementById('job-db-fields');
  fs.hidden = isDB; fs.disabled = isDB;
  dbf.hidden = !isDB; dbf.disabled = !isDB;
  const sel = form.elements['agent_id'];
  let keep = false;
  for (const opt of sel.options) {
    if (!opt.value) continue;
    const match = (opt.dataset.agentType || 'filesystem') === type;
    opt.hidden = !match; opt.disabled = !match;
    if (match && opt.selected) keep = true;
  }
  if (!keep) sel.value = '';
  setDBEngine(form.elements['db_engine'].value);
}

function setDBEngine(engine) {
  document.querySelectorAll('#job-db-fields .db-engine-opts').forEach(el => {
    const on = el.dataset.engine === engine;
    el.hidden = !on;
    el.querySelectorAll('input,select').forEach(c => { c.disabled = !on; });
  });
  const port = jobForm().elements['db_port'];
  if (port) port.placeholder = { postgres: '5432', mysql: '3306', mongodb: '27017' }[engine] || '';
}

function newJob() {
  const form = jobForm();
  form.reset();
  form.dataset.jobId = '';
  document.getElementById('db-password-hint').hidden = true;
  setJobType('filesystem');
  document.getElementById('job-modal-title').innerText = 'Create Backup Job';
  document.getElementById('job-submit').innerText = 'Create Job';
  openModal('modal-add-job');
}

async function editJob(jobId) {
  try {
    const resp = await apiFetch(`/api/v1/jobs/${jobId}`);
    if (!resp.ok) throw new Error('Failed to load job');
    const job = await resp.json();
    const form = jobForm();
    form.reset();
    form.dataset.jobId = job.id;
    form.elements['name'].value = job.name || '';
    const jobType = job.job_type || 'filesystem';
    form.elements['job_type'].value = jobType;
    form.elements['agent_id'].value = job.agent_id || '';
    form.elements['target_id'].value = job.target_id || '';
    form.elements['backup_paths'].value = (job.backup_paths || []).join('\n');
    form.elements['exclude_paths'].value = (job.exclude_paths || []).join('\n');
    document.getElementById('db-password-hint').hidden = true;
    if (jobType === 'database' && job.db_config) {
      const dc = job.db_config;
      form.elements['db_engine'].value = dc.engine || 'postgres';
      form.elements['db_host'].value = dc.host || '';
      form.elements['db_port'].value = dc.port || '';
      form.elements['db_user'].value = dc.user || '';
      form.elements['db_profile'].value = dc.profile || '';
      form.elements['db_databases'].value = (dc.databases || []).join('\n');
      form.elements['db_tls_mode'].value = (dc.tls && dc.tls.mode) || '';
      form.elements['db_tls_ca_file'].value = (dc.tls && dc.tls.ca_file) || '';
      form.elements['db_compression'].value = dc.compression || 'none';
      form.elements['db_backup_id'].value = dc.backup_id || '';
      document.getElementById('db-password-hint').hidden = !dc.has_password;
      const pg = dc.postgres || {}, my = dc.mysql || {}, mo = dc.mongodb || {};
      form.elements['pg_mode'].value = pg.mode || 'dump';
      form.elements['pg_format'].value = pg.format || 'custom';
      form.elements['pg_role_passwords'].value = pg.role_passwords || 'auto';
      form.elements['pg_globals'].checked = pg.globals !== false;
      form.elements['my_single_transaction'].checked = my.single_transaction !== false;
      form.elements['my_include_binlogs'].checked = !!my.include_binlogs;
      form.elements['mongo_read_preference'].value = mo.read_preference || '';
      form.elements['mongo_auth_source'].value = mo.auth_source || '';
      form.elements['mongo_replica_set'].value = mo.replica_set || '';
      form.elements['mongo_oplog'].checked = mo.oplog !== false;
    }
    setJobType(jobType);
    form.elements['agent_id'].value = job.agent_id || '';
    form.elements['schedule_cron'].value = job.schedule_cron || '';
    form.elements['direct_pbs'].checked = !!job.direct_pbs;
    form.elements['enabled'].checked = !!job.enabled;
    const rp = job.retention_policy || {};
    form.elements['keep_last'].value = rp.keep_last ?? 7;
    form.elements['keep_daily'].value = rp.keep_daily ?? 7;
    form.elements['keep_weekly'].value = rp.keep_weekly ?? 4;
    form.elements['keep_monthly'].value = rp.keep_monthly ?? 12;
    document.getElementById('job-modal-title').innerText = 'Edit Backup Job';
    document.getElementById('job-submit').innerText = 'Save Changes';
    openModal('modal-add-job');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function submitJobForm(e) {
  e.preventDefault();
  const form = e.target;
  const formData = new FormData(form);
  const jobId = form.dataset.jobId || '';

  const pathsRaw = formData.get('backup_paths') || '';
  const backupPaths = pathsRaw.split('\n').map(p => p.trim()).filter(p => p.length > 0);

  const excludeRaw = formData.get('exclude_paths') || '';
  const excludePaths = excludeRaw.split('\n').map(p => p.trim()).filter(p => p.length > 0);

  const payload = {
    name: formData.get('name'),
    agent_id: formData.get('agent_id'),
    target_id: formData.get('target_id'),
    schedule_cron: formData.get('schedule_cron') || '',
    backup_paths: backupPaths,
    exclude_paths: excludePaths,
    retention_policy: {
      keep_last: parseInt(formData.get('keep_last') || '7'),
      keep_daily: parseInt(formData.get('keep_daily') || '7'),
      keep_weekly: parseInt(formData.get('keep_weekly') || '4'),
      keep_monthly: parseInt(formData.get('keep_monthly') || '12'),
    },
    enabled: formData.get('enabled') === 'on',
    direct_pbs: formData.get('direct_pbs') === 'on',
    job_type: formData.get('job_type') || 'filesystem'
  };

  if (payload.job_type === 'database') {
    payload.backup_paths = [];
    payload.exclude_paths = [];
    const lines = (formData.get('db_databases') || '').split('\n').map(p => p.trim()).filter(p => p.length > 0);
    const engine = formData.get('db_engine');
    const dc = {
      engine: engine,
      host: (formData.get('db_host') || '').trim(),
      port: parseInt(formData.get('db_port') || '0') || 0,
      user: formData.get('db_user') || '',
      profile: formData.get('db_profile') || '',
      tls: { mode: formData.get('db_tls_mode') || '', ca_file: formData.get('db_tls_ca_file') || '' },
      databases: lines,
      compression: formData.get('db_compression') || 'none',
      backup_id: formData.get('db_backup_id') || ''
    };
    if (formData.get('db_password')) dc.password = formData.get('db_password');
    if (formData.get('db_clear_password') === 'on') dc.clear_password = true;
    if (engine === 'postgres') {
      dc.postgres = { mode: formData.get('pg_mode'), format: formData.get('pg_format'), role_passwords: formData.get('pg_role_passwords'), globals: formData.get('pg_globals') === 'on' };
    } else if (engine === 'mysql') {
      dc.mysql = { single_transaction: formData.get('my_single_transaction') === 'on', include_binlogs: formData.get('my_include_binlogs') === 'on' };
    } else if (engine === 'mongodb') {
      dc.mongodb = { oplog: formData.get('mongo_oplog') === 'on', read_preference: formData.get('mongo_read_preference') || '', auth_source: formData.get('mongo_auth_source') || '', replica_set: formData.get('mongo_replica_set') || '' };
    }
    payload.db_config = dc;
  }

  try {
    const resp = await apiFetch(jobId ? `/api/v1/jobs/${jobId}` : '/api/v1/jobs', {
      method: jobId ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const errData = await resp.json();
      throw new Error(errData.error || 'Failed to save job');
    }

    showToast(jobId ? 'Backup job updated' : 'Backup job created successfully!', 'success');
    closeModal('modal-add-job');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function triggerJobRun(jobId) {
  if (!confirm('Start an immediate backup execution for this job?')) return;

  try {
    const resp = await apiFetch(`/api/v1/jobs/${jobId}/run`, { method: 'POST' });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Failed to trigger job');
    }
    showToast('Backup run initiated!', 'success');
    setTimeout(() => window.location.href = '/runs', 1000);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function revokeToken(tokenId) {
  if (!confirm('Invalidate this enrollment token? Agents can no longer enroll with it.')) return;
  try {
    const resp = await apiFetch(`/api/v1/tokens/${tokenId}`, { method: 'DELETE' });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Failed to revoke token');
    }
    showToast('Enrollment token invalidated', 'success');
    setTimeout(() => window.location.reload(), 600);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function cancelRun(runId) {
  if (!confirm('Cancel this backup run? The agent will stop uploading and the run is marked cancelled.')) return;

  try {
    const resp = await apiFetch(`/api/v1/runs/${runId}/cancel`, { method: 'POST' });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to cancel run');
    }
    const data = await resp.json();
    showToast(data.status === 'cancelled' ? 'Run cancelled' : 'Cancellation requested', 'success');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteResource(type, id) {
  if (!confirm(`Are you sure you want to delete this ${type}?`)) return;

  try {
    const resp = await apiFetch(`/api/v1/${type}/${id}`, { method: 'DELETE' });
    if (!resp.ok) throw new Error(`Failed to delete ${type}`);
    showToast(`${type} deleted`, 'success');
    setTimeout(() => window.location.reload(), 600);
  } catch (err) {
    showToast(err.message, 'error');
  }
}
