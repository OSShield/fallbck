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

// 6. Action Handlers for Target, Job, and Run Creation
// ---- Target form: shared by the Targets modal and the onboarding page -----------

function targetForm() { return document.getElementById('target-form'); }

// resetTargetForm prepares a form for a new target (token required)
function resetTargetForm(form) {
  form.reset();
  form.dataset.targetId = '';
  const tok = form.querySelector('[name="auth_token"]');
  tok.required = true;
  tok.placeholder = 'user@pbs!fallbck:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx';
  const hint = form.querySelector('#target-token-hint');
  if (hint) hint.innerText = 'Encrypted on the server. Agents never receive this token directly.';
  form.elements['tls_verify'].checked = true;
}

function loadTargetIntoForm(form, t) {
  form.reset();
  form.dataset.targetId = t.id;
  form.elements['name'].value = t.name || '';
  form.elements['endpoint'].value = t.endpoint || '';
  form.elements['datastore'].value = t.datastore || '';
  form.elements['namespace'].value = t.namespace || '';
  form.elements['fingerprint'].value = t.fingerprint || '';
  form.elements['pxar_format'].value = t.pxar_format || 'v1';
  form.elements['tls_verify'].checked = !!t.tls_verify;
  const tok = form.querySelector('[name="auth_token"]');
  tok.value = '';
  tok.required = false;
  tok.placeholder = t.has_token ? 'leave blank to keep the current token' : 'no token stored — enter one';
  const hint = form.querySelector('#target-token-hint');
  if (hint) hint.innerText = 'Leave blank to keep the stored token, or enter a new one to replace it.';
}

function buildTargetPayload(form) {
  const fd = new FormData(form);
  return {
    name: fd.get('name'),
    target_type: fd.get('target_type') || 'pbs',
    endpoint: fd.get('endpoint'),
    datastore: fd.get('datastore'),
    namespace: fd.get('namespace') || '',
    auth_token: fd.get('auth_token') || '',
    fingerprint: fd.get('fingerprint') || '',
    tls_verify: fd.get('tls_verify') === 'on',
    pxar_format: fd.get('pxar_format') || 'v1'
  };
}

// saveTarget creates (no id) or updates a target and returns the stored record
async function saveTarget(payload, id) {
  const resp = await apiFetch(id ? `/api/v1/targets/${id}` : '/api/v1/targets', {
    method: id ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to save target');
  }
  return resp.json();
}

function newTarget() {
  const form = targetForm();
  resetTargetForm(form);
  document.getElementById('target-modal-title').innerText = 'Add Proxmox Backup Server Target';
  document.getElementById('target-submit').innerText = 'Save Target';
  openModal('modal-add-target');
}

async function editTarget(id) {
  try {
    const resp = await apiFetch(`/api/v1/targets/${id}`);
    if (!resp.ok) throw new Error('Failed to load target');
    loadTargetIntoForm(targetForm(), await resp.json());
    document.getElementById('target-modal-title').innerText = 'Edit PBS Target';
    document.getElementById('target-submit').innerText = 'Save Changes';
    openModal('modal-add-target');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function submitTargetForm(e) {
  e.preventDefault();
  const form = e.target;
  const id = form.dataset.targetId || '';
  try {
    await saveTarget(buildTargetPayload(form), id);
    showToast(id ? 'Backup target updated' : 'Backup target added successfully!', 'success');
    closeModal('modal-add-target');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Clone a target into another namespace (Targets page modal; the onboarding page
// calls cloneTarget directly)
function openCloneTarget(id, name, namespace) {
  const form = document.getElementById('clone-target-form');
  form.reset();
  form.dataset.targetId = id;
  document.getElementById('clone-target-source').innerText = name + (namespace ? ` (namespace ${namespace})` : ' (root namespace)');
  form.elements['name'].value = name + '-';
  openModal('modal-clone-target');
}

async function cloneTarget(id, payload) {
  const resp = await apiFetch(`/api/v1/targets/${id}/clone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to clone target');
  }
  return resp.json();
}

async function submitCloneTargetForm(e) {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  try {
    const t = await cloneTarget(form.dataset.targetId, { name: fd.get('name'), namespace: fd.get('namespace') });
    showToast(`Target ${t.name} created`, 'success');
    closeModal('modal-clone-target');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ---- Job form: the Jobs modal and the onboarding page share the field partials ----
// (partials/job_fields_*.html, job_schedule.html) and these helpers. Every helper
// takes the form element; the modal wrappers pass their own.

function jobForm() { return document.getElementById('job-form'); }

// lines splits a textarea into trimmed, non-empty lines
function formLines(fd, name) {
  return (fd.get(name) || '').split('\n').map(p => p.trim()).filter(p => p.length > 0);
}

// setJobTypeIn switches the form between the per-type fieldsets and, when the form
// has an agent select, limits it to agents that can run the type
function setJobTypeIn(form, type) {
  const isDB = type === 'database';
  const isPVE = type === 'pve';
  const isDocker = type === 'docker';
  const isK8s = type === 'kubernetes'; // cluster jobs: only the onboarding form carries that fieldset
  const show = (id, on) => {
    const el = form.querySelector('#' + id);
    if (el) { el.hidden = !on; el.disabled = !on; }
  };
  show('job-fs-fields', !isDB && !isPVE && !isDocker && !isK8s);
  show('job-db-fields', isDB);
  show('job-pve-fields', isPVE);
  show('job-docker-fields', isDocker);
  show('job-k8s-fields', isK8s);
  filterJobAgents(form, type);
  if (form.elements['db_engine']) setDBEngine(form.elements['db_engine'].value, form);
  else updateDBTarget(form);
}

function setJobType(type) { setJobTypeIn(jobForm(), type); }

// filterJobAgents limits the agent select (when the form has one) to agents that can
// run the type; database jobs also go by the engine: a kubernetes agent dumps from a
// pod (everything but SQL Server), a filesystem agent offers the engines it reported
function filterJobAgents(form, type) {
  const sel = form.elements['agent_id'];
  if (!sel || sel.tagName !== 'SELECT') return;
  const engine = form.elements['db_engine'] ? form.elements['db_engine'].value : '';
  let keep = false;
  for (const opt of sel.options) {
    if (!opt.value) continue;
    const agentType = opt.dataset.agentType || 'filesystem';
    let match = agentType === type;
    if (type === 'database') {
      const engines = (opt.dataset.dbEngines || '').split(',').filter(Boolean);
      if (agentType === 'filesystem') match = engines.length ? engines.includes(engine) : (opt.dataset.db === 'true' && engine !== 'mssql');
      else match = (agentType === 'kubernetes' || agentType === 'database') && engine !== 'mssql';
    }
    if (type === 'pve') match = agentType === 'filesystem' && opt.dataset.pve === 'true';
    if (type === 'docker') match = agentType === 'filesystem' && opt.dataset.docker === 'true';
    opt.hidden = !match; opt.disabled = !match;
    if (match && opt.selected) keep = true;
  }
  if (!keep) sel.value = '';
}

// selectedAgentIsK8s: from the agent select, or from data-agent-type when the form
// has a fixed agent (onboarding)
function selectedAgentIsK8s(form = jobForm()) {
  const el = form.elements['agent_id'];
  if (el && el.tagName === 'SELECT') {
    const opt = el.options[el.selectedIndex];
    return !!(opt && opt.value && opt.dataset.agentType === 'kubernetes');
  }
  return form.dataset.agentType === 'kubernetes';
}

// A database job on a kubernetes agent needs the in-cluster target settings; the
// agent-side credential profile and TLS files do not apply there
function updateDBTarget(form = jobForm()) {
  const block = form.querySelector('#db-k8s-fields');
  if (!block) return;
  const typeEl = form.elements['job_type'];
  const type = typeEl ? typeEl.value : (form.dataset.jobType || 'filesystem');
  const k8s = selectedAgentIsK8s(form) && type === 'database';
  block.hidden = !k8s;
  block.querySelectorAll('input').forEach(c => { c.disabled = !k8s; });
  form.elements['db_k8s_namespace'].required = k8s;
  form.elements['db_profile'].disabled = k8s;
  form.elements['db_tls_ca_file'].disabled = k8s;
  const label = form.querySelector('#db-host-label');
  const mssql = form.elements['db_engine'] && form.elements['db_engine'].value === 'mssql';
  if (label) label.innerText = k8s ? 'Host (optional when a Service is given)' : mssql ? 'Host (host\\instance for a named instance)' : 'Host (or unix socket path)';
  updateDBProfiles(form);
}

// updateDBProfiles fills the credential-profile datalist with the names the selected
// agent reported in its inventory (names, engine, user and host only: the agent
// never sends passwords), narrowed to the chosen engine. The form's agent select
// carries them in data-db-profiles ("name:engine,..."); a fixed-agent form
// (onboarding) sets form.dataset.dbProfiles instead.
function updateDBProfiles(form = jobForm()) {
  const list = form.querySelector('#db-profile-list');
  const hint = form.querySelector('#db-profile-hint');
  if (!list) return;
  const sel = form.elements['agent_id'];
  let raw = form.dataset.dbProfiles || '';
  let host = form.dataset.hostname || '';
  let chosen = true;
  if (sel && sel.tagName === 'SELECT') {
    const opt = sel.options[sel.selectedIndex];
    chosen = !!(opt && opt.value);
    raw = chosen ? (opt.dataset.dbProfiles || '') : '';
    host = chosen ? (opt.dataset.hostname || '') : '';
  }
  const engine = form.elements['db_engine'] ? form.elements['db_engine'].value : '';
  const all = raw.split(',').filter(Boolean).map(p => { const i = p.indexOf(':'); return i < 0 ? { name: p, engine: '' } : { name: p.slice(0, i), engine: p.slice(i + 1) }; });
  const match = all.filter(p => !engine || !p.engine || p.engine === engine);
  list.innerHTML = '';
  match.forEach(p => { const o = document.createElement('option'); o.value = p.name; list.appendChild(o); });
  if (!hint) return;
  if (!chosen) hint.innerText = 'Choose an agent to see the profiles configured on it.';
  else if (match.length) hint.innerText = `Profiles on ${host || 'the agent'} for ${engine || 'this engine'}: ${match.map(p => p.name).join(', ')}`;
  else if (all.length) hint.innerText = `${host || 'The agent'} has no ${engine} profile (${all.map(p => p.name + ' [' + p.engine + ']').join(', ')}). Create one there: fallbck-agent database profile create --name <name> --engine ${engine} ...`;
  else hint.innerText = `No profiles reported by ${host || 'the agent'} yet. Create one on the host: fallbck-agent database profile create --name <name> --engine ${engine || '<engine>'} --user <user> --ask-password`;
}

function setDBEngine(engine, form = jobForm()) {
  form.querySelectorAll('.db-engine-opts').forEach(el => {
    const on = el.dataset.engine === engine;
    el.hidden = !on;
    el.querySelectorAll('input,select').forEach(c => { c.disabled = !on; });
  });
  const port = form.elements['db_port'];
  if (port) port.placeholder = { postgres: '5432', mysql: '3306', mongodb: '27017', mssql: '1433' }[engine] || '';
  // SQL Server: no gzip of the spool (native compression instead), user optional
  const mssql = engine === 'mssql';
  if (form.elements['db_compression']) form.elements['db_compression'].disabled = mssql;
  if (form.elements['db_user']) form.elements['db_user'].placeholder = mssql ? 'blank = Windows integrated authentication' : 'backup';
  const typeEl = form.elements['job_type'];
  filterJobAgents(form, typeEl ? typeEl.value : (form.dataset.jobType || 'filesystem'));
  updateDBTarget(form);
  updateDBProfiles(form);
}

// loadJobIntoForm fills every field of a job form from an API job record
function loadJobIntoForm(form, job) {
  form.reset();
  form.dataset.jobId = job.id;
  form.elements['name'].value = job.name || '';
  const jobType = job.job_type || 'filesystem';
  if (form.elements['job_type']) form.elements['job_type'].value = jobType;
  form.dataset.jobType = jobType;
  form.elements['agent_id'].value = job.agent_id || '';
  form.elements['target_id'].value = job.target_id || '';
  form.elements['backup_paths'].value = (job.backup_paths || []).join('\n');
  form.elements['exclude_paths'].value = (job.exclude_paths || []).join('\n');
  const hint = form.querySelector('#db-password-hint');
  if (hint) hint.hidden = true;
  if (jobType === 'pve') {
    const pc = job.pve_config || {};
    form.elements['pve_data_paths'].value = (pc.data_paths || []).join('\n');
    form.elements['pve_exclude_paths'].value = (pc.exclude_paths || []).join('\n');
    form.elements['pve_include_root_home'].checked = pc.include_root_home !== false;
    form.elements['pve_include_guest_images'].checked = !!pc.include_guest_images;
  }
  if (jobType === 'docker') {
    const dc = job.docker_config || {};
    form.elements['docker_exclude_containers'].value = (dc.exclude_containers || []).join('\n');
    form.elements['docker_exclude_volumes'].value = (dc.exclude_volumes || []).join('\n');
    form.elements['docker_pause_containers'].value = (dc.pause_containers || []).join('\n');
    form.elements['docker_exclude_paths'].value = (dc.exclude_paths || []).join('\n');
    form.elements['docker_host_paths'].value = (dc.host_paths || []).join('\n');
    form.elements['docker_images'].value = dc.images || 'refs';
    form.elements['docker_include_unused_volumes'].checked = dc.include_unused_volumes !== false;
    form.elements['docker_include_stopped'].checked = dc.include_stopped !== false;
  }
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
    if (hint) hint.hidden = !dc.has_password;
    const pg = dc.postgres || {}, my = dc.mysql || {}, mo = dc.mongodb || {};
    form.elements['pg_mode'].value = pg.mode || 'dump';
    form.elements['pg_format'].value = pg.format || 'custom';
    form.elements['pg_role_passwords'].value = pg.role_passwords || 'auto';
    form.elements['pg_globals'].checked = pg.globals !== false;
    form.elements['my_single_transaction'].checked = my.single_transaction !== false;
    form.elements['my_include_binlogs'].checked = !!my.include_binlogs;
    form.elements['my_per_database'].checked = !!my.per_database;
    form.elements['mongo_read_preference'].value = mo.read_preference || '';
    form.elements['mongo_auth_source'].value = mo.auth_source || '';
    form.elements['mongo_replica_set'].value = mo.replica_set || '';
    form.elements['mongo_oplog'].checked = mo.oplog !== false;
    const ms = dc.mssql || {};
    form.elements['ms_mode'].value = ms.mode || 'auto';
    form.elements['ms_full_every_days'].value = ms.full_every_days || 7;
    form.elements['ms_backup_dir'].value = ms.backup_dir || '';
    form.elements['ms_agent_dir'].value = ms.agent_dir || '';
    form.elements['ms_include_log'].checked = !!ms.include_log;
    form.elements['ms_compression'].checked = !!ms.compression;
    form.elements['ms_copy_only'].checked = !!ms.copy_only;
    const k8s = dc.kubernetes || {};
    form.elements['db_k8s_namespace'].value = k8s.namespace || '';
    form.elements['db_k8s_service'].value = k8s.service || '';
    form.elements['db_k8s_secret'].value = k8s.secret_name || '';
    form.elements['db_k8s_password_key'].value = k8s.password_key || '';
    form.elements['db_k8s_user_key'].value = k8s.user_key || '';
    form.elements['db_k8s_tools_image'].value = k8s.tools_image || '';
  }
  setJobTypeIn(form, jobType);
  form.elements['agent_id'].value = job.agent_id || '';
  updateDBTarget(form);
  form.elements['schedule_cron'].value = job.schedule_cron || '';
  form.elements['direct_pbs'].checked = !!job.direct_pbs;
  form.elements['enabled'].checked = !!job.enabled;
}

// buildJobPayload turns a job form into the API payload (filesystem, database,
// Proxmox VE and Docker types; kubernetes cluster jobs use buildK8sPayload)
function buildJobPayload(form) {
  const fd = new FormData(form);
  const typeEl = form.elements['job_type'];
  const payload = {
    name: fd.get('name'),
    agent_id: fd.get('agent_id'),
    target_id: fd.get('target_id'),
    schedule_cron: fd.get('schedule_cron') || '',
    backup_paths: formLines(fd, 'backup_paths'),
    exclude_paths: formLines(fd, 'exclude_paths'),
    enabled: fd.get('enabled') === 'on',
    direct_pbs: fd.get('direct_pbs') === 'on',
    job_type: (typeEl ? typeEl.value : form.dataset.jobType) || 'filesystem'
  };

  if (payload.job_type === 'pve') {
    payload.backup_paths = [];
    payload.exclude_paths = [];
    payload.pve_config = {
      data_paths: formLines(fd, 'pve_data_paths'),
      exclude_paths: formLines(fd, 'pve_exclude_paths'),
      include_root_home: fd.get('pve_include_root_home') === 'on',
      include_guest_images: fd.get('pve_include_guest_images') === 'on'
    };
  }

  if (payload.job_type === 'docker') {
    payload.backup_paths = [];
    payload.exclude_paths = [];
    payload.docker_config = {
      exclude_containers: formLines(fd, 'docker_exclude_containers'),
      exclude_volumes: formLines(fd, 'docker_exclude_volumes'),
      pause_containers: formLines(fd, 'docker_pause_containers'),
      exclude_paths: formLines(fd, 'docker_exclude_paths'),
      host_paths: formLines(fd, 'docker_host_paths'),
      images: fd.get('docker_images') || 'refs',
      include_unused_volumes: fd.get('docker_include_unused_volumes') === 'on',
      include_stopped: fd.get('docker_include_stopped') === 'on'
    };
  }

  if (payload.job_type === 'database') {
    payload.backup_paths = [];
    payload.exclude_paths = [];
    const engine = fd.get('db_engine');
    const dc = {
      engine: engine,
      host: (fd.get('db_host') || '').trim(),
      port: parseInt(fd.get('db_port') || '0') || 0,
      user: fd.get('db_user') || '',
      profile: fd.get('db_profile') || '',
      tls: { mode: fd.get('db_tls_mode') || '', ca_file: fd.get('db_tls_ca_file') || '' },
      databases: formLines(fd, 'db_databases'),
      compression: fd.get('db_compression') || 'none',
      backup_id: fd.get('db_backup_id') || ''
    };
    if (fd.get('db_password')) dc.password = fd.get('db_password');
    if (fd.get('db_clear_password') === 'on') dc.clear_password = true;
    if (selectedAgentIsK8s(form)) {
      dc.profile = '';
      dc.tls.ca_file = '';
      dc.kubernetes = {
        namespace: (fd.get('db_k8s_namespace') || '').trim(),
        service: (fd.get('db_k8s_service') || '').trim(),
        secret_name: (fd.get('db_k8s_secret') || '').trim(),
        password_key: (fd.get('db_k8s_password_key') || '').trim(),
        user_key: (fd.get('db_k8s_user_key') || '').trim(),
        tools_image: (fd.get('db_k8s_tools_image') || '').trim()
      };
    }
    if (engine === 'postgres') {
      dc.postgres = { mode: fd.get('pg_mode'), format: fd.get('pg_format'), role_passwords: fd.get('pg_role_passwords'), globals: fd.get('pg_globals') === 'on' };
    } else if (engine === 'mysql') {
      dc.mysql = { single_transaction: fd.get('my_single_transaction') === 'on', include_binlogs: fd.get('my_include_binlogs') === 'on', per_database: fd.get('my_per_database') === 'on' };
    } else if (engine === 'mssql') {
      dc.compression = 'none';
      dc.mssql = { mode: fd.get('ms_mode') || 'auto', full_every_days: parseInt(fd.get('ms_full_every_days') || '7') || 7, include_log: fd.get('ms_include_log') === 'on', compression: fd.get('ms_compression') === 'on', copy_only: fd.get('ms_copy_only') === 'on', backup_dir: (fd.get('ms_backup_dir') || '').trim(), agent_dir: (fd.get('ms_agent_dir') || '').trim() };
    } else if (engine === 'mongodb') {
      dc.mongodb = { oplog: fd.get('mongo_oplog') === 'on', read_preference: fd.get('mongo_read_preference') || '', auth_source: fd.get('mongo_auth_source') || '', replica_set: fd.get('mongo_replica_set') || '' };
    }
    payload.db_config = dc;
  }
  return payload;
}

// saveJob creates (no id) or updates a job and returns the stored record
async function saveJob(payload, jobId) {
  const resp = await apiFetch(jobId ? `/api/v1/jobs/${jobId}` : '/api/v1/jobs', {
    method: jobId ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(errData.error || 'Failed to save job');
  }
  return resp.json();
}

async function editJob(jobId) {
  try {
    const resp = await apiFetch(`/api/v1/jobs/${jobId}`);
    if (!resp.ok) throw new Error('Failed to load job');
    loadJobIntoForm(jobForm(), await resp.json());
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
  const jobId = form.dataset.jobId || '';
  try {
    await saveJob(buildJobPayload(form), jobId);
    showToast(jobId ? 'Backup job updated' : 'Backup job created successfully!', 'success');
    closeModal('modal-add-job');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// triggerJob starts a run and returns {run_id, ...} as the API reports it
async function triggerJob(jobId) {
  const resp = await apiFetch(`/api/v1/jobs/${jobId}/run`, { method: 'POST' });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to trigger job');
  }
  return resp.json().catch(() => ({}));
}

async function triggerJobRun(jobId) {
  if (!confirm('Start an immediate backup execution for this job?')) return;
  try {
    await triggerJob(jobId);
    showToast('Backup run initiated!', 'success');
    setTimeout(() => window.location.href = '/runs', 1000);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ---- Backup Jobs page filters ---------------------------------------------------
// Client-side over the rendered rows; the state lives in the URL, so links such as
// /jobs?type=kubernetes (the old Kubernetes page redirects there) open filtered.

const JOB_FILTERS = ['type', 'enabled', 'lastrun', 'agent', 'target', 'schedule'];

function initJobFilters() {
  const bar = document.getElementById('job-filters');
  if (!bar) return;
  const q = new URLSearchParams(window.location.search);
  JOB_FILTERS.forEach(k => {
    const el = bar.querySelector(`[name="f_${k}"]`);
    if (!el) return;
    if (q.get(k)) el.value = q.get(k);
    el.addEventListener('change', applyJobFilters);
  });
  applyJobFilters();
}

function applyJobFilters() {
  const bar = document.getElementById('job-filters');
  if (!bar) return;
  const want = {};
  JOB_FILTERS.forEach(k => { want[k] = (bar.querySelector(`[name="f_${k}"]`) || {}).value || ''; });
  let shown = 0;
  document.querySelectorAll('tr.job-row').forEach(row => {
    const d = row.dataset;
    // "running" covers every state of a run that has not ended yet
    const lastrun = RUN_ACTIVE.includes(d.lastrun) ? 'running' : d.lastrun;
    const ok = (!want.type || d.type === want.type) && (!want.enabled || d.enabled === want.enabled) &&
      (!want.lastrun || lastrun === want.lastrun) && (!want.agent || d.agent === want.agent) &&
      (!want.target || d.target === want.target) && (!want.schedule || d.schedule === want.schedule);
    row.hidden = !ok;
    if (ok) shown++;
  });
  const count = document.getElementById('job-count');
  if (count) count.innerText = shown;
  const none = document.getElementById('job-no-match');
  if (none) none.hidden = shown !== 0;
  const q = new URLSearchParams();
  JOB_FILTERS.forEach(k => { if (want[k]) q.set(k, want[k]); });
  const qs = q.toString();
  history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : ''));
}

function clearJobFilters() {
  const bar = document.getElementById('job-filters');
  if (!bar) return;
  JOB_FILTERS.forEach(k => { const el = bar.querySelector(`[name="f_${k}"]`); if (el) el.value = ''; });
  applyJobFilters();
}

document.addEventListener('DOMContentLoaded', initJobFilters);

// ---- Kubernetes cluster job form ------------------------------------------------

function k8sJobForm() { return document.getElementById('k8s-job-form'); }

const K8S_DEFAULT_NS_EXCLUDES = ['kube-system', 'kube-node-lease', 'kube-public'];

function loadK8sJobIntoForm(form, job) {
  form.reset();
  form.dataset.jobId = job.id;
  form.elements['name'].value = job.name || '';
  form.elements['agent_id'].value = job.agent_id || '';
  form.elements['target_id'].value = job.target_id || '';
  form.elements['schedule_cron'].value = job.schedule_cron || '';
  form.elements['direct_pbs'].checked = !!job.direct_pbs;
  form.elements['enabled'].checked = !!job.enabled;
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
  form.elements['k8s_live_fallback'].checked = vols.allow_live_fallback !== false;
  form.elements['k8s_continue'].checked = vols.continue_on_error !== false;
}

function buildK8sPayload(form) {
  const fd = new FormData(form);
  const overrides = {};
  formLines(fd, 'k8s_snapshot_overrides').forEach(l => {
    const idx = l.indexOf('=');
    if (idx > 0) overrides[l.slice(0, idx).trim()] = l.slice(idx + 1).trim();
  });
  return {
    name: fd.get('name'),
    agent_id: fd.get('agent_id'),
    target_id: fd.get('target_id'),
    job_type: 'kubernetes',
    schedule_cron: fd.get('schedule_cron') || '',
    backup_paths: [],
    exclude_paths: [],
    enabled: fd.get('enabled') === 'on',
    direct_pbs: fd.get('direct_pbs') === 'on',
    k8s_config: {
      namespaces: { include: formLines(fd, 'k8s_ns_include'), exclude: formLines(fd, 'k8s_ns_exclude') },
      label_selector: fd.get('k8s_label_selector') || '',
      resources: {
        exclude_extra: formLines(fd, 'k8s_resources_exclude'),
        include_secrets: fd.get('k8s_include_secrets') === 'on',
      },
      volumes: {
        mode: fd.get('k8s_volumes_mode'),
        label_selector: fd.get('k8s_volumes_selector') || '',
        storage_classes: formLines(fd, 'k8s_storage_classes'),
        exclude_storage_classes: formLines(fd, 'k8s_exclude_storage_classes'),
        snapshot_class_overrides: overrides,
        allow_live_fallback: fd.get('k8s_live_fallback') === 'on',
        continue_on_error: fd.get('k8s_continue') === 'on',
        parallelism: parseInt(fd.get('k8s_parallelism') || '2'),
        snapshot_timeout: fd.get('k8s_snapshot_timeout') || '',
        volume_timeout: fd.get('k8s_volume_timeout') || '',
      },
    },
  };
}

async function editK8sJob(jobId) {
  try {
    const resp = await apiFetch(`/api/v1/jobs/${jobId}`);
    if (!resp.ok) throw new Error('Failed to load job');
    loadK8sJobIntoForm(k8sJobForm(), await resp.json());
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
  const jobId = form.dataset.jobId || '';
  try {
    await saveJob(buildK8sPayload(form), jobId);
    showToast(jobId ? 'Cluster job updated' : 'Cluster job created', 'success');
    closeModal('modal-add-k8s-job');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Agent status page: both actions reach the agent through a Temporal activity on
// its task queue, so they need it online; the API answers 504 when it is not
async function refreshAgentInventory(agentId) {
  const btn = document.getElementById('agent-refresh-btn');
  if (btn) { btn.disabled = true; btn.innerText = 'Refreshing…'; }
  try {
    const resp = await apiFetch(`/api/v1/agents/${agentId}/inventory`, { method: 'POST' });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || `Inventory refresh failed (${resp.status})`);
    }
    showToast('Inventory refreshed', 'success');
    setTimeout(() => window.location.reload(), 500);
  } catch (err) {
    showToast(err.message, 'error');
    if (btn) { btn.disabled = false; btn.innerText = 'Refresh inventory'; }
  }
}

async function loadAgentLogs(agentId) {
  const btn = document.getElementById('agent-logs-btn');
  const card = document.getElementById('agent-logs-card');
  const pre = document.getElementById('agent-logs-pre');
  const meta = document.getElementById('agent-logs-meta');
  if (btn) { btn.disabled = true; btn.innerText = 'Fetching…'; }
  try {
    const resp = await apiFetch(`/api/v1/agents/${agentId}/logs`, { method: 'POST' });
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(body.error || `Log fetch failed (${resp.status})`);
    const text = (body.lines || '').replace(/\s+$/, '');
    const count = text ? text.split('\n').length : 0;
    if (pre) pre.innerText = text || '(the agent has no buffered log lines)';
    if (meta) meta.innerText = `${count} lines · level ${body.level || '?'} · ${body.at ? new Date(body.at).toLocaleString() : ''}`;
    if (card) { card.hidden = false; card.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.innerText = 'View logs'; }
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

let _runPollTimer = null;
const RUN_ACTIVE = ['pending', 'running', 'cancelling'];
async function loadRunDetail(runId) {
  const root = document.getElementById('run-detail-root');
  try {
    const resp = await apiFetch(`/api/v1/runs/${runId}`);
    if (!resp.ok) throw new Error(resp.status === 404 ? 'Run not found' : 'Failed to load run');
    const run = await resp.json();
    _runDetail = run;
    root.innerHTML = renderRun(run);
    if (_runPollTimer) clearTimeout(_runPollTimer);
    if (RUN_ACTIVE.includes(run.status)) {
      _runPollTimer = setTimeout(() => loadRunDetail(runId), 3500);
    }
  } catch (err) {
    if (!_runDetail) root.innerHTML = rdCard('Error', `<p style="color:var(--danger-text);">${rdEsc(err.message)}</p>`);
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
  const typeLabel = { filesystem: 'Filesystem', database: 'Database', kubernetes: 'Kubernetes', pve: 'Proxmox VE host', docker: 'Docker host' }[type] || type;

  const active = RUN_ACTIVE.includes(run.status);
  let html = '';
  if (active) html += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;color:var(--text-muted);font-size:13px;"><span class="badge badge-warning"><span class="badge-dot"></span> Live</span> auto-refreshing every few seconds…</div>`;
  html += rdCard(run.job_name || 'Backup run', rdKV([
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

  if (active && run.progress) html += renderProgress(run.progress);

  if (type === 'database') html += renderDBDetail(d.manifest || {});
  else if (type === 'kubernetes') html += renderK8sDetail(d.manifest || {});
  else if (type === 'pve') html += renderPVEDetail(d.manifest || {});
  else if (type === 'docker') html += renderDockerDetail(d.manifest || {});
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
  if (d.reuse) {
    const r = d.reuse;
    body += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Change detection</div>` + rdKV([
      ['Files', String(r.files)], ['Unchanged (not re-read)', String(r.reused_files)],
      ['Reused content', rdBytes(r.reused_bytes)], ['Referenced previous chunks', rdBytes(r.injected_bytes)],
      ['Runs re-read (padding)', r.rejected_runs ? String(r.rejected_runs) : '0'],
    ]);
  }
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
  if (m.mysql) {
    html += rdCard('MySQL dump', rdKV([
      ['Flavor', rdEsc(m.mysql.flavor || '')], ['Layout', m.mysql.per_database ? 'one file per database' : 'single --all-databases file'],
      ['Dump files', String((m.mysql.dump_files || []).length)], ['Single transaction', m.mysql.single_transaction ? 'yes' : 'no'],
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
  if (m.mssql) {
    const ms = m.mssql;
    html += rdCard('SQL Server', rdKV([
      ['Edition', rdEsc(ms.edition || '')], ['Mode', rdEsc(ms.mode || '')],
      ['Backup directory', rdMono(ms.backup_dir || '') + (ms.agent_dir ? ' (agent: ' + rdMono(ms.agent_dir) + ')' : '')],
      ['Compression', ms.compression ? 'native' : 'none'], ['Checksum', ms.checksum ? 'yes' : 'no'], ['Copy-only', ms.copy_only ? 'yes' : ''],
    ]));
    const sets = (ms.backup_sets || []).map(b => [rdEsc(b.database), rdEsc(b.type), rdEsc(b.recovery_model || ''), rdMono(b.first_lsn || ''), rdMono(b.last_lsn || ''),
      rdBytes(b.compressed_bytes || b.backup_bytes || 0), rdMono(rdShort(b.backup_set_uuid || '')), rdEsc(b.reason || '')]);
    html += rdCard('SQL Server backup sets', rdTable(['Database', 'Type', 'Recovery', 'First LSN', 'Last LSN', 'Size', 'Set', 'Why this type'], sets));
    if (ms.skipped && ms.skipped.length) html += rdCard('Skipped databases', rdTable(['Database', 'Reason'], ms.skipped.map(x => [rdEsc(x.database), rdEsc(x.reason)])));
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

function renderPVEDetail(m) {
  const h = m.host || {};
  const p = m.packages || {};
  let html = rdCard('Proxmox VE host', rdKV([
    ['Host', rdEsc(h.hostname || '')], ['Node', rdEsc(h.node || '')],
    ['pve-manager', rdEsc(h.pve_version || '-')], ['Kernel', rdEsc(h.kernel || '-')], ['OS', rdEsc(h.os || '-')],
    ['Packages', `${p.installed || 0} installed, ${p.manual || 0} manual`],
  ]));
  const guests = (m.guests || []).map(g => [String(g.vmid), rdEsc(g.type), rdEsc(g.name || ''), rdMono(g.config_file)]);
  html += rdCard('Guests (configuration only)', rdTable(['VMID', 'Type', 'Name', 'Config'], guests));
  const storages = (m.storages || []).map(s => [rdEsc(s.id), rdEsc(s.type), rdEsc(s.path || s.pool || s.export || ''), rdEsc((s.content || []).join(', ')), s.shared ? 'yes' : '', s.disabled ? 'yes' : '']);
  html += rdCard('Storages', rdTable(['ID', 'Type', 'Path / pool', 'Content', 'Shared', 'Disabled'], storages));
  const disks = (m.disks || []).map(d => [rdMono(d.path), rdEsc(d.model || ''), rdEsc(d.serial || ''), rdBytes(d.size_bytes), d.partition_table ? 'saved' : '-']);
  html += rdCard('Disks', rdTable(['Device', 'Model', 'Serial', 'Size', 'Partition table'], disks));
  const entries = (m.entries || []).map(e => [rdMono(e.name), rdMono(e.source), rdEsc(e.kind)]);
  let layout = rdTable(['Archive entry', 'Source', 'Kind'], entries);
  if (m.excludes && m.excludes.length) layout += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Excludes</div>${rdChips(m.excludes)}`;
  html += rdCard('Archive layout (' + rdEsc((m.snapshot || {}).archive || 'pve.pxar') + ')', layout);
  const failed = (m.collected || []).filter(c => c.error);
  if (failed.length || (m.warnings && m.warnings.length)) {
    let b = '';
    if (failed.length) b += '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Collectors that failed (best effort)</div>' +
      rdTable(['Collector', 'Command', 'Error'], failed.map(c => [rdEsc(c.name), rdMono(c.command || ''), rdEsc(c.error)]));
    if (m.warnings && m.warnings.length) b += '<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Warnings</div><ul style="margin:4px 0 0 18px;font-size:13px;">' + m.warnings.map(n => `<li>${rdEsc(n)}</li>`).join('') + '</ul>';
    html += rdCard('Warnings', b);
  }
  if (m.restore && m.restore.commands && m.restore.commands.length)
    html += rdCard('Restore', (m.restore.summary ? `<p style="font-size:13px;margin-bottom:8px;">${rdEsc(m.restore.summary)}</p>` : '') +
      (m.restore.script ? `<p style="font-size:13px;margin-bottom:8px;">The full runbook is stored in the archive as <code>${rdEsc(m.restore.script)}</code>.</p>` : '') +
      rdPre(m.restore.commands.join('\n')));
  return html;
}

function renderDockerDetail(m) {
  const h = m.host || {};
  let html = rdCard('Docker host', rdKV([
    ['Host', rdEsc((m.generator || {}).hostname || h.hostname || '')], ['Docker', rdEsc(h.docker_version || '-') + (h.api_version ? ` (API ${rdEsc(h.api_version)})` : '')],
    ['OS', rdEsc(h.os || '-')], ['Kernel', rdEsc(h.kernel || '-')], ['Storage driver', rdEsc(h.storage_driver || '-')],
    ['Root dir', rdMono(h.root_dir || '-')], ['Volume access', rdEsc(h.volume_access || '-')],
    ['Swarm', rdEsc(h.swarm || 'inactive') + (h.swarm_manager ? ' (manager)' : '')],
    ['Containers', `${h.containers || 0} (${h.containers_running || 0} running)`],
  ]));
  const containers = (m.containers || []).map(c => [rdEsc(c.name), rdEsc(c.state || ''), rdEsc(c.image || ''), rdEsc(c.compose_project ? `${c.compose_project} / ${c.compose_service || ''}` : ''),
    rdEsc((c.mounts || []).filter(x => x.type === 'volume').map(x => x.volume).join(', ')), c.paused_for_backup ? 'paused' : '', rdEsc(c.skipped || '')]);
  html += rdCard('Containers', rdTable(['Name', 'State', 'Image', 'Compose', 'Volumes', 'Consistency', 'Skipped'], containers));
  const volumes = (m.volumes || []).map(v => [rdEsc(v.name), rdEsc(v.driver || ''), rdEsc((v.used_by || []).join(', ')), v.entry ? rdMono(v.entry) : '-', rdEsc(v.access || ''), rdEsc((v.paused_containers || []).join(', ')), rdEsc(v.skipped || '')]);
  html += rdCard('Volumes', rdTable(['Name', 'Driver', 'Used by', 'Archive entry', 'Access', 'Paused', 'Skipped'], volumes));
  const nets = (m.networks || []).filter(n => !n.builtin).map(n => [rdEsc(n.name), rdEsc(n.driver || ''), rdEsc((n.subnets || []).map(s => s.subnet).filter(Boolean).join(', ')), n.internal ? 'yes' : '', rdEsc((n.containers || []).join(', '))]);
  if (nets.length) html += rdCard('Networks (user-defined)', rdTable(['Name', 'Driver', 'Subnets', 'Internal', 'Containers'], nets));
  const compose = (m.compose_projects || []).map(p => [rdEsc(p.name), rdMono(p.working_dir || ''), rdEsc((p.services || []).join(', ')), rdEsc((p.archived || []).map(f => f.source).join(', ')) || '<span style="color:var(--warning-text)">none archived</span>']);
  if (compose.length) html += rdCard('Compose projects', rdTable(['Project', 'Working dir', 'Services', 'Archived files'], compose));
  const images = (m.images || []).map(i => [rdEsc((i.repo_tags || [])[0] || rdShort((i.id || '').replace('sha256:', ''))), rdEsc(((i.repo_digests || [])[0] || '').split('@')[1] || '').slice(0, 19), rdBytes(i.size_bytes || 0), i.saved ? 'saved' : (i.local ? 'local, not saved' : 'reference'), rdEsc((i.used_by || []).join(', '))]);
  html += rdCard('Images', rdTable(['Image', 'Digest', 'Size', 'In backup', 'Used by'], images));
  const entries = (m.entries || []).map(e => [rdMono(e.name), rdMono(e.source), rdEsc(e.kind)]);
  let layout = rdTable(['Archive entry', 'Source', 'Kind'], entries);
  if (m.host_paths && m.host_paths.length) layout += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Host paths</div>` + rdTable(['Path', 'Archive entry', 'Access', 'Skipped'], m.host_paths.map(h => [rdMono(h.path), h.entry ? rdMono(h.entry) : '-', rdEsc(h.access || ''), rdEsc(h.skipped || '')]));
  if (m.excludes && m.excludes.length) layout += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Excludes</div>${rdChips(m.excludes)}`;
  if (m.bind_mounts && m.bind_mounts.length) layout += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Bind mounts (archived only when listed as a host path)</div>` + rdTable(['Host path', 'Containers'], m.bind_mounts.map(b => [rdMono(b.source), rdEsc((b.containers || []).join(', '))]));
  html += rdCard('Archive layout (' + rdEsc((m.snapshot || {}).archive || 'docker.pxar') + ')', layout);
  const failed = (m.collected || []).filter(c => c.error);
  if (failed.length || (m.warnings && m.warnings.length)) {
    let b = '';
    if (failed.length) b += '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Collectors that failed (best effort)</div>' +
      rdTable(['Collector', 'Source', 'Error'], failed.map(c => [rdEsc(c.name), rdMono(c.endpoint || ''), rdEsc(c.error)]));
    if (m.warnings && m.warnings.length) b += '<div style="margin-top:12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;">Warnings</div><ul style="margin:4px 0 0 18px;font-size:13px;">' + m.warnings.map(n => `<li>${rdEsc(n)}</li>`).join('') + '</ul>';
    html += rdCard('Warnings', b);
  }
  if (m.restore && m.restore.commands && m.restore.commands.length)
    html += rdCard('Restore', (m.restore.summary ? `<p style="font-size:13px;margin-bottom:8px;">${rdEsc(m.restore.summary)}</p>` : '') +
      (m.restore.script ? `<p style="font-size:13px;margin-bottom:8px;">The full runbook is stored in the archive as <code>${rdEsc(m.restore.script)}</code>.</p>` : '') +
      rdPre(m.restore.commands.join('\n')));
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

function renderProgress(p) {
  let body = '';
  if (p.phase) body += `<div style="margin-bottom:12px;"><span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;">Current step</span><div style="font-size:14px;margin-top:2px;">${rdEsc(p.phase)}</div></div>`;
  const items = p.items || {};
  const keys = Object.keys(items).sort((a, b) => (items[a].name || a).localeCompare(items[b].name || b));
  if (keys.length) {
    const done = keys.filter(k => ['completed', 'skipped'].includes(items[k].status)).length;
    const rows = keys.map(k => {
      const it = items[k];
      const st = it.status === 'completed' ? 'completed' : it.status === 'failed' ? 'failed' : it.status === 'skipped' ? 'cancelled' : it.status === 'running' ? 'running' : 'pending';
      return [
        rdEsc(it.name || k), rdStatus(st), rdEsc(it.mode || ''),
        it.bytes_uploaded ? rdBytes(it.bytes_uploaded) : '-',
        it.error ? `<span style="color:var(--danger-text);">${rdEsc(it.error.split('\n')[0].slice(0, 140))}</span>` : rdEsc(it.note || ''),
      ];
    });
    body += `<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;">Items (${done}/${keys.length} done)</div>` +
      rdTable(['Item', 'Status', 'Mode', 'Uploaded', 'Detail'], rows);
  }
  if (!body) body = '<p style="color:var(--text-muted);font-size:13px;">Starting…</p>';
  return rdCard('Live progress', body);
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
