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
    } else if (os === 'k8s') {
      codeEl.innerText = `helm install fallbck-k8s-agent ./deploy/helm/fallbck-k8s-agent \\\n  --namespace fallbck --create-namespace \\\n  --set server.url=${serverUrl} \\\n  --set clusterName=<cluster name> \\\n  --set enrollment.key=${data.raw_token}`;
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

// ---- Kubernetes job form ----------------------------------------------------

function k8sJobForm() { return document.getElementById('k8s-job-form'); }

const K8S_DEFAULT_NS_EXCLUDES = ['kube-system', 'kube-node-lease', 'kube-public'];

function newK8sJob() {
  const form = k8sJobForm();
  form.reset();
  form.dataset.jobId = '';
  form.elements['k8s_ns_exclude'].value = K8S_DEFAULT_NS_EXCLUDES.join('\n');
  document.getElementById('k8s-job-modal-title').innerText = 'Create Cluster Backup Job';
  document.getElementById('k8s-job-submit').innerText = 'Create Job';
  openModal('modal-add-k8s-job');
}

async function editK8sJob(jobId) {
  try {
    const resp = await apiFetch(`/api/v1/jobs/${jobId}`);
    if (!resp.ok) throw new Error('Failed to load job');
    const job = await resp.json();
    const form = k8sJobForm();
    form.reset();
    form.dataset.jobId = job.id;
    form.elements['name'].value = job.name || '';
    form.elements['agent_id'].value = job.agent_id || '';
    form.elements['target_id'].value = job.target_id || '';
    form.elements['schedule_cron'].value = job.schedule_cron || '';
    form.elements['direct_pbs'].checked = !!job.direct_pbs;
    form.elements['enabled'].checked = !!job.enabled;
    const rp = job.retention_policy || {};
    form.elements['keep_last'].value = rp.keep_last ?? 7;
    form.elements['keep_daily'].value = rp.keep_daily ?? 7;
    form.elements['keep_weekly'].value = rp.keep_weekly ?? 4;
    form.elements['keep_monthly'].value = rp.keep_monthly ?? 12;
    const kc = job.k8s_config || {};
    const ns = kc.namespaces || {};
    const res = kc.resources || {};
    const vols = kc.volumes || {};
    form.elements['k8s_ns_include'].value = (ns.include || []).join('\n');
    form.elements['k8s_ns_exclude'].value = (ns.exclude || []).join('\n');
    form.elements['k8s_label_selector'].value = kc.label_selector || '';
    form.elements['k8s_resources_exclude'].value = (res.exclude_extra || []).join('\n');
    form.elements['k8s_include_secrets'].checked = res.include_secrets !== false;
    form.elements['k8s_volumes_mode'].value = vols.mode || 'all';
    form.elements['k8s_volumes_selector'].value = vols.label_selector || '';
    form.elements['k8s_parallelism'].value = vols.parallelism || 2;
    form.elements['k8s_storage_classes'].value = (vols.storage_classes || []).join('\n');
    form.elements['k8s_exclude_storage_classes'].value = (vols.exclude_storage_classes || []).join('\n');
    form.elements['k8s_snapshot_overrides'].value = Object.entries(vols.snapshot_class_overrides || {}).map(([k, v]) => `${k}=${v}`).join('\n');
    form.elements['k8s_snapshot_timeout'].value = vols.snapshot_timeout || '';
    form.elements['k8s_volume_timeout'].value = vols.volume_timeout || '';
    form.elements['k8s_forget_days'].value = vols.forget_orphans_after_days || 0;
    form.elements['k8s_live_fallback'].checked = vols.allow_live_fallback !== false;
    form.elements['k8s_continue'].checked = vols.continue_on_error !== false;
    document.getElementById('k8s-job-modal-title').innerText = 'Edit Cluster Backup Job';
    document.getElementById('k8s-job-submit').innerText = 'Save Changes';
    openModal('modal-add-k8s-job');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function submitK8sJobForm(e) {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  const jobId = form.dataset.jobId || '';
  const lines = name => (fd.get(name) || '').split('\n').map(s => s.trim()).filter(Boolean);
  const overrides = {};
  lines('k8s_snapshot_overrides').forEach(l => {
    const idx = l.indexOf('=');
    if (idx > 0) overrides[l.slice(0, idx).trim()] = l.slice(idx + 1).trim();
  });
  const payload = {
    name: fd.get('name'),
    agent_id: fd.get('agent_id'),
    target_id: fd.get('target_id'),
    job_type: 'kubernetes',
    schedule_cron: fd.get('schedule_cron') || '',
    backup_paths: [],
    exclude_paths: [],
    retention_policy: {
      keep_last: parseInt(fd.get('keep_last') || '7'),
      keep_daily: parseInt(fd.get('keep_daily') || '7'),
      keep_weekly: parseInt(fd.get('keep_weekly') || '4'),
      keep_monthly: parseInt(fd.get('keep_monthly') || '12'),
    },
    enabled: fd.get('enabled') === 'on',
    direct_pbs: fd.get('direct_pbs') === 'on',
    k8s_config: {
      namespaces: { include: lines('k8s_ns_include'), exclude: lines('k8s_ns_exclude') },
      label_selector: fd.get('k8s_label_selector') || '',
      resources: {
        exclude_extra: lines('k8s_resources_exclude'),
        include_secrets: fd.get('k8s_include_secrets') === 'on',
      },
      volumes: {
        mode: fd.get('k8s_volumes_mode'),
        label_selector: fd.get('k8s_volumes_selector') || '',
        storage_classes: lines('k8s_storage_classes'),
        exclude_storage_classes: lines('k8s_exclude_storage_classes'),
        snapshot_class_overrides: overrides,
        allow_live_fallback: fd.get('k8s_live_fallback') === 'on',
        continue_on_error: fd.get('k8s_continue') === 'on',
        parallelism: parseInt(fd.get('k8s_parallelism') || '2'),
        snapshot_timeout: fd.get('k8s_snapshot_timeout') || '',
        volume_timeout: fd.get('k8s_volume_timeout') || '',
        forget_orphans_after_days: parseInt(fd.get('k8s_forget_days') || '0'),
      },
    },
  };

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
    showToast(jobId ? 'Cluster job updated' : 'Cluster job created', 'success');
    closeModal('modal-add-k8s-job');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function toggleAgentDebug(agentId, enable) {
  try {
    const resp = await apiFetch(`/api/v1/agents/${agentId}/debug`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: enable })
    });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || 'Failed to toggle debug logging');
    }
    showToast(enable ? 'Debug logging enabled — the agent applies it on its next heartbeat (~30s)' : 'Debug logging disabled', 'success');
    setTimeout(() => window.location.reload(), 700);
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

// ===== Run detail page =========================================================

let _runDetail = null;

function rdBytes(n) {
  if (n === undefined || n === null) return '-';
  n = Number(n);
  if (!isFinite(n)) return '-';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(2)) + ' ' + u[i];
}
function rdEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function rdStatus(s) {
  const m = {
    completed: ['badge-success', 'Completed'], running: ['badge-warning', 'Running'],
    failed: ['badge-danger', 'Failed'], cancelling: ['badge-warning', 'Cancelling'],
    cancelled: ['badge-neutral', 'Cancelled'], pending: ['badge-neutral', 'Pending'],
  };
  const [cls, label] = m[s] || ['badge-neutral', s || 'Unknown'];
  return `<span class="badge ${cls}"><span class="badge-dot"></span> ${rdEsc(label)}</span>`;
}
function rdCard(title, body, opts) {
  const o = opts || {};
  return `<div class="card" style="margin-bottom: 16px;">
    <div class="card-header"><h3 class="card-title">${rdEsc(title)}</h3>${o.actions || ''}</div>
    <div style="padding: ${o.pad || '16px'};">${body}</div></div>`;
}
function rdKV(pairs) {
  const cells = pairs.filter(p => p && p[1] !== undefined && p[1] !== null && p[1] !== '')
    .map(([k, v]) => `<div><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.03em;">${rdEsc(k)}</div><div style="font-size:14px;margin-top:2px;">${v}</div></div>`).join('');
  return `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;">${cells}</div>`;
}
function rdTable(headers, rows) {
  if (!rows.length) return '<p style="color:var(--text-muted);font-size:13px;">None.</p>';
  const th = headers.map(h => `<th>${rdEsc(h)}</th>`).join('');
  const tr = rows.map(r => `<tr>${r.map(c => `<td style="font-size:13px;">${c}</td>`).join('')}</tr>`).join('');
  return `<div class="table-container"><table><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table></div>`;
}
function rdChips(items) {
  if (!items || !items.length) return '<span style="color:var(--text-muted);font-size:13px;">None.</span>';
  return items.map(i => `<code style="display:inline-block;margin:2px 4px 2px 0;font-size:12px;">${rdEsc(i)}</code>`).join('');
}
function rdPre(text) {
  return `<pre style="background:var(--bg-subtle);padding:12px;border-radius:var(--radius-sm);font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto;margin:0;">${rdEsc(text)}</pre>`;
}
function rdMono(s) { return `<code style="font-family:var(--font-mono);font-size:12px;">${rdEsc(s)}</code>`; }
function rdShort(h) { return h ? String(h).slice(0, 12) : ''; }

async function loadRunDetail(runId) {
  const root = document.getElementById('run-detail-root');
  try {
    const resp = await apiFetch(`/api/v1/runs/${runId}`);
    if (!resp.ok) throw new Error(resp.status === 404 ? 'Run not found' : 'Failed to load run');
    const run = await resp.json();
    _runDetail = run;
    root.innerHTML = renderRun(run);
  } catch (err) {
    root.innerHTML = rdCard('Error', `<p style="color:var(--danger-text);">${rdEsc(err.message)}</p>`);
  }
}

function renderRun(run) {
  let duration = '-';
  if (run.start_time) {
    const end = run.end_time ? new Date(run.end_time) : new Date();
    const secs = Math.max(0, Math.round((end - new Date(run.start_time)) / 1000));
    duration = secs >= 3600 ? `${Math.floor(secs / 3600)}h ${Math.floor(secs % 3600 / 60)}m ${secs % 60}s`
      : secs >= 60 ? `${Math.floor(secs / 60)}m ${secs % 60}s` : `${secs}s`;
  }
  const d = run.details || {};
  const type = d.type || 'filesystem';
  const typeLabel = { filesystem: 'Filesystem', database: 'Database', kubernetes: 'Kubernetes' }[type] || type;

  let html = rdCard(run.job_name || 'Backup run', rdKV([
    ['Status', rdStatus(run.status)],
    ['Type', rdEsc(typeLabel)],
    ['Agent', rdEsc(run.agent_name || '-')],
    ['Started', run.start_time ? rdEsc(new Date(run.start_time).toLocaleString()) : '-'],
    ['Duration', rdEsc(duration)],
    ['PBS snapshot', run.pbs_snapshot_id ? rdMono(run.pbs_snapshot_id) : '-'],
  ]));

  html += rdCard('Transfer', rdKV([
    ['Protected data', rdBytes(run.bytes_scanned)],
    ['Uploaded to PBS', rdBytes(run.bytes_uploaded)],
    ['Deduplication', run.dedup_ratio ? run.dedup_ratio.toFixed(2) + 'x' : '-'],
    ['Chunks', run.chunk_count != null ? String(run.chunk_count) : '-'],
  ]));

  if (run.error_message) {
    html += rdCard('Error', rdPre(run.error_message));
  }

  if (type === 'database') html += renderDBDetail(d.manifest || {});
  else if (type === 'kubernetes') html += renderK8sDetail(d.manifest || {});
  else if (d.archives || d.paths) html += renderFsDetail(d);

  if (run.log_tail) html += rdCard('Agent log (captured at the run)', rdPre(run.log_tail));

  if (run.details && Object.keys(run.details).length) {
    html += `<details style="margin-bottom:16px;"><summary style="cursor:pointer;padding:12px 16px;background:var(--bg-subtle);border-radius:var(--radius-sm);font-weight:600;font-size:13px;">Raw details JSON</summary>${rdPre(JSON.stringify(run.details, null, 2))}</details>`;
  }
  return html;
}

function renderFsDetail(d) {
  let body = '';
  body += `<div style="margin-bottom:12px;"><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Paths</div>${rdChips(d.paths)}</div>`;
  if (d.exclude_paths && d.exclude_paths.length)
    body += `<div style="margin-bottom:12px;"><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Exclude patterns</div>${rdChips(d.exclude_paths)}</div>`;
  const rows = (d.archives || []).map(a => [
    rdMono(a.name), rdEsc(a.kind || ''), rdBytes(a.size_bytes),
    String(a.chunks || 0), String(a.new_chunks || 0), String(a.reused_chunks || 0),
    a.dedup ? a.dedup.toFixed(2) + 'x' : '-',
  ]);
  body += `<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;">Archives</div>` +
    rdTable(['Archive', 'Kind', 'Size', 'Chunks', 'New', 'Reused', 'Dedup'], rows);
  if (d.warnings && d.warnings.length)
    body += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Warnings</div>` +
      rdTable(['Path', 'Message'], d.warnings.map(w => [rdMono(w.path || ''), rdEsc(w.message)]));
  return rdCard('Filesystem archives (format ' + rdEsc(d.format || '-') + ')', body);
}

function renderDBDetail(m) {
  const srv = m.server || {};
  let html = rdCard('Database server', rdKV([
    ['Engine', rdEsc(m.engine)], ['Version', rdEsc(srv.version || '-')],
    ['Host', rdEsc((srv.host || '') + (srv.port ? ':' + srv.port : ''))],
    ['Flavor', rdEsc(srv.flavor || '')], ['Replica', srv.is_replica ? 'yes' : ''],
  ]));
  const dbRows = (m.databases || []).map(db => [
    rdEsc(db.name), rdEsc(db.format || ''), rdBytes(db.size_bytes),
    db.sha256 ? rdMono(rdShort(db.sha256)) : '-', db.duration_ms ? (db.duration_ms / 1000).toFixed(1) + 's' : '-',
  ]);
  html += rdCard('Databases', rdTable(['Database', 'Format', 'Size', 'SHA256', 'Duration'], dbRows));

  if (m.postgres && m.postgres.basebackup) {
    const b = m.postgres.basebackup;
    html += rdCard('PostgreSQL basebackup', rdKV([
      ['Mode', rdEsc(m.postgres.mode)], ['Timeline', b.timeline], ['Compression', rdEsc(b.compression)],
      ['WAL start', rdMono(b.wal_start_lsn || '')], ['WAL end', rdMono(b.wal_end_lsn || '')],
      ['WAL files', rdEsc([b.wal_start_file, b.wal_end_file].filter(Boolean).join(' … '))],
    ]));
  }
  if (m.mysql && m.mysql.binlog) {
    const bl = m.mysql.binlog;
    html += rdCard('MySQL binary logs', rdKV([
      ['Enabled', bl.enabled ? 'yes' : 'no'], ['Position', rdEsc((bl.file || '') + ':' + (bl.position ?? ''))],
      ['GTID', rdMono(bl.gtid || '')], ['Covers from', bl.covers_from ? rdMono(bl.covers_from.file + ':' + bl.covers_from.position) : ''],
      ['Covers to', bl.covers_to ? rdMono(bl.covers_to.file + ':' + bl.covers_to.position) : ''],
      ['Binlog files', bl.files ? String(bl.files.length) : '0'],
      ['Chain gap', bl.chain_gap ? 'yes' : ''], ['Chain reset', bl.chain_reset ? 'yes' : ''],
    ]));
  }
  if (m.mongodb) {
    html += rdCard('MongoDB', rdKV([
      ['Oplog', m.mongodb.oplog ? 'captured' : 'no'], ['Read preference', rdEsc(m.mongodb.read_preference || '')],
      ['Databases', (m.mongodb.databases || []).join(', ')], ['Per-database', m.mongodb.per_database ? 'yes' : 'no'],
    ]));
  }
  if ((m.warnings && m.warnings.length) || (m.notes && m.notes.length)) {
    let b = '';
    if (m.notes && m.notes.length) b += '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Notes</div><ul style="margin:4px 0 12px 18px;font-size:13px;">' + m.notes.map(n => `<li>${rdEsc(n)}</li>`).join('') + '</ul>';
    if (m.warnings && m.warnings.length) b += '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Warnings</div><ul style="margin:4px 0 0 18px;font-size:13px;">' + m.warnings.map(n => `<li>${rdEsc(n)}</li>`).join('') + '</ul>';
    html += rdCard('Notes & warnings', b);
  }
  if (m.restore && m.restore.commands && m.restore.commands.length)
    html += rdCard('Restore', (m.restore.summary ? `<p style="font-size:13px;margin-bottom:8px;">${rdEsc(m.restore.summary)}</p>` : '') + rdPre(m.restore.commands.join('\n')));
  return html;
}

function renderK8sDetail(m) {
  const k = m.kubernetes || {};
  const res = m.resources || {};
  let html = rdCard('Cluster', rdKV([
    ['Cluster', rdEsc((m.generator || {}).cluster || '')], ['Server version', rdEsc(k.server_version || '')],
    ['CSI snapshots', k.snapshot_crd ? 'available' : 'not available'],
    ['Secrets included', res.secrets_included ? 'yes' : 'no'],
  ]));

  const vols = m.volumes || [];
  const vrows = vols.map(v => [
    rdEsc(v.namespace + '/' + v.pvc), rdEsc(v.mode || ''), rdEsc(v.consistency || ''),
    rdStatus(v.status === 'completed' ? 'completed' : v.status === 'skipped' ? 'cancelled' : 'failed'),
    rdBytes(v.bytes_uploaded), v.snapshot_id ? rdMono(rdShort(v.snapshot_id.split('/').pop())) : '-',
    v.error ? `<span style="color:var(--danger-text);">${rdEsc(v.error.split('\n')[0].slice(0, 160))}</span>` : '',
  ]);
  const okCount = vols.filter(v => v.status === 'completed').length;
  html += rdCard(`Persistent volumes (${okCount}/${vols.length} ok)`,
    rdTable(['PVC', 'Mode', 'Consistency', 'Status', 'Uploaded', 'Snapshot', 'Error'], vrows));

  const counts = res.counts || {};
  const crows = Object.keys(counts).sort().map(k => [rdMono(k), String(counts[k])]);
  let resBody = `<div style="margin-bottom:12px;"><div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Namespaces</div>${rdChips(res.namespaces)}</div>`;
  resBody += `<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;">Resource counts</div>` + rdTable(['Group/Resource', 'Count'], crows);
  if (res.excluded && res.excluded.length) resBody += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Excluded types</div>${rdChips(res.excluded)}`;
  if (res.failed_groups && res.failed_groups.length) resBody += `<div style="margin-top:12px;font-size:11px;color:var(--danger-text);text-transform:uppercase;">Discovery-failed API groups</div>${rdChips(res.failed_groups)}`;
  html += rdCard('API resources', resBody);

  const warns = (m.warnings || []).concat(res.warnings || []);
  if (warns.length) html += rdCard('Warnings', '<ul style="margin:0 0 0 18px;font-size:13px;">' + warns.map(w => `<li>${rdEsc(w)}</li>`).join('') + '</ul>');
  if (m.restore && m.restore.commands && m.restore.commands.length)
    html += rdCard('Restore', (m.restore.summary ? `<p style="font-size:13px;margin-bottom:8px;">${rdEsc(m.restore.summary)}</p>` : '') + rdPre(m.restore.commands.join('\n')));
  return html;
}

function downloadRunDetails() {
  if (!_runDetail) return;
  const blob = new Blob([JSON.stringify(_runDetail, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `run-${_runDetail.id || 'details'}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
