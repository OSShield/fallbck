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
    auth_token_encrypted: formData.get('auth_token') || '',
    fingerprint: formData.get('fingerprint') || '',
    tls_verify: formData.get('tls_verify') === 'on'
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

async function submitJobForm(e) {
  e.preventDefault();
  const form = e.target;
  const formData = new FormData(form);

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
    enabled: formData.get('enabled') === 'on'
  };

  try {
    const resp = await apiFetch('/api/v1/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const errData = await resp.json();
      throw new Error(errData.error || 'Failed to create job');
    }

    showToast('Backup job created successfully!', 'success');
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
