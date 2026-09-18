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

// 5. Agent guided installation wizard (Agents page)
// Step 1 picks the agent type, step 2 the platform it runs on, step 3 shows the
// package repository, install and enrollment instructions for that combination.
// One single-use enrollment token is minted per wizard session, the first time
// step 3 is shown, and reused while the administrator moves back and forth.
const agentWizard = { step: 1, type: '', target: '', token: '' };

const AGENT_WIZARD_TYPES = {
  files:      { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  proxmox:    { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  docker:     { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  database:   { label: 'database agent',   pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  kubernetes: { label: 'Kubernetes agent' }
};

function openAddAgentModal() {
  agentWizard.step = 1;
  agentWizard.type = '';
  agentWizard.target = '';
  agentWizard.token = ''; // a token minted for an earlier session may already be used up
  document.querySelectorAll('#modal-add-agent .wizard-option').forEach(o => o.classList.remove('selected'));
  openModal('modal-add-agent');
  agentWizardRender();
}

function agentWizardSelect(el) {
  const kind = el.dataset.kind; // 'type' or 'target'
  if (kind === 'type' && agentWizard.type !== el.dataset.value) agentWizard.target = '';
  agentWizard[kind] = el.dataset.value;
  el.parentElement.querySelectorAll('.wizard-option').forEach(o => o.classList.toggle('selected', o === el));
  agentWizardRender();
}

function agentWizardKey(event, el) {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    agentWizardSelect(el);
  }
}

function agentWizardNext() {
  if (agentWizard.step === 1 && !agentWizard.type) return;
  if (agentWizard.step === 2 && !agentWizard.target) return;
  if (agentWizard.step < 3) agentWizard.step++;
  agentWizardRender();
}

function agentWizardBack() {
  if (agentWizard.step > 1) agentWizard.step--;
  agentWizardRender();
}

function agentWizardRender() {
  const modal = document.getElementById('modal-add-agent');
  if (!modal) return;
  const step = agentWizard.step;
  modal.querySelectorAll('.wizard-page').forEach(p => p.classList.toggle('active', p.dataset.step === String(step)));
  modal.querySelectorAll('.wizard-progress-step').forEach(p => {
    const n = Number(p.dataset.step);
    p.classList.toggle('active', n === step);
    p.classList.toggle('done', n < step);
  });

  // Step 2 only offers the platforms the chosen agent type runs on; a type with a
  // single platform (Kubernetes, Proxmox VE) gets it pre-selected.
  if (step === 2) {
    document.getElementById('wizard-type-label').innerText = (AGENT_WIZARD_TYPES[agentWizard.type] || {}).label || 'agent';
    const options = Array.from(modal.querySelectorAll('#wizard-target-options .wizard-option'));
    const visible = options.filter(o => o.dataset.types.split(',').includes(agentWizard.type));
    options.forEach(o => { o.hidden = !visible.includes(o); });
    if (visible.length === 1 && !agentWizard.target) agentWizard.target = visible[0].dataset.value;
    options.forEach(o => o.classList.toggle('selected', !o.hidden && o.dataset.value === agentWizard.target));
  }

  document.getElementById('wizard-back').hidden = step === 1;
  const next = document.getElementById('wizard-next');
  next.hidden = step === 3;
  next.disabled = (step === 1 && !agentWizard.type) || (step === 2 && !agentWizard.target);
  document.getElementById('wizard-done').hidden = step !== 3;

  if (step === 3) agentWizardRenderInstructions();
}

async function agentWizardToken() {
  if (agentWizard.token) return agentWizard.token;
  const resp = await apiFetch('/api/v1/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `Wizard-${agentWizard.type}-${new Date().toISOString().slice(0, 19)}`, max_uses: 1, expires_at: new Date(Date.now() + 24 * 3600 * 1000) })
  });
  if (!resp.ok) throw new Error('Token generation failed');
  const data = await resp.json();
  agentWizard.token = data.raw_token;
  return agentWizard.token;
}

async function agentWizardRenderInstructions() {
  const root = document.getElementById('wizard-instructions');
  root.innerHTML = '';
  const wait = document.createElement('p');
  wait.className = 'wizard-lead';
  wait.innerText = 'Generating a single-use enrollment token...';
  root.appendChild(wait);

  let token;
  try {
    token = await agentWizardToken();
  } catch (err) {
    wait.innerText = `Error: ${err.message}`;
    return;
  }
  if (agentWizard.step !== 3) return; // the administrator went back meanwhile

  root.innerHTML = '';
  const sections = agentWizardSections(agentWizard.type, agentWizard.target, window.location.origin, token);
  sections.forEach((s, i) => root.appendChild(agentWizardSection(s, i)));
}

// The server URL and token are inserted as text nodes, never as markup
function agentWizardSection(s, i) {
  const wrap = document.createElement('div');
  wrap.className = 'wizard-section';
  const h = document.createElement('h4');
  h.innerText = `${i + 1}. ${s.title}`;
  wrap.appendChild(h);
  if (s.text) {
    const p = document.createElement('p');
    p.innerText = s.text;
    wrap.appendChild(p);
  }
  if (s.code) {
    const id = `wizard-code-${i}`;
    const code = document.createElement('div');
    code.className = 'code-block';
    code.id = id;
    code.innerText = s.code;
    wrap.appendChild(code);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary btn-sm';
    btn.innerText = 'Copy';
    btn.onclick = () => copyToClipboard(id);
    wrap.appendChild(btn);
  }
  if (s.note) {
    const n = document.createElement('p');
    n.className = 'wizard-note';
    n.innerText = s.note;
    wrap.appendChild(n);
  }
  return wrap;
}

const AGENT_WIZARD_RELEASES = 'https://github.com/osshield/fallbck/releases';
const AGENT_WIZARD_RAW = 'https://raw.githubusercontent.com/osshield/fallbck/main';

// Package repository setup per platform. Proxmox VE nodes are administered as root
// and ship without sudo, so their commands carry no sudo prefix.
function agentWizardRepo(target, pkg) {
  const sudo = target === 'proxmox' ? '' : 'sudo ';
  switch (target) {
    case 'debian':
    case 'proxmox':
      return `${sudo}apt-get update\n${sudo}apt-get -y install gnupg2 apt-transport-https curl\n\n` +
        `${sudo}install -d -m 0755 /etc/apt/keyrings\n` +
        `curl -fsSL https://deb.pkg.lv/key | ${sudo}gpg --dearmor -o /etc/apt/keyrings/pkg-lv.gpg\n` +
        `echo "deb [signed-by=/etc/apt/keyrings/pkg-lv.gpg] https://deb.pkg.lv all main" | ${sudo}tee /etc/apt/sources.list.d/pkg-lv.list\n` +
        `${sudo}apt update\n${sudo}apt install ${pkg}`;
    case 'rhel':
      return `sudo tee /etc/yum.repos.d/pkg-lv.repo <<'EOF'\n[pkg-lv]\nname=pkg.lv\nbaseurl=https://rpm.pkg.lv\nenabled=1\ngpgcheck=1\ngpgkey=https://rpm.pkg.lv/key\nEOF\n` +
        `sudo rpm --import https://rpm.pkg.lv/key\nsudo yum install ${pkg}`;
    case 'alpine':
      return `apk update\napk add curl\ncd /etc/apk/keys && curl -JO https://alpine.pkg.lv/key\n` +
        `echo "https://alpine.pkg.lv" >> /etc/apk/repositories\napk update\napk add ${pkg}`;
  }
  return '';
}

// Manual install from the GitHub release for distributions without a package:
// binary, state directories, environment template and a service unit.
function agentWizardManualLinux(type, pkg, svc) {
  const asset = 'fallbck_agent_Linux_${ARCH}.tar.gz';
  const dataDir = '/var/lib/fallbck/agent';
  const env = 'agent.env';
  const install = `ARCH=x86_64   # or arm64\n` +
    `curl -fsSL -o /tmp/${pkg}.tar.gz ${AGENT_WIZARD_RELEASES}/latest/download/${asset}\n` +
    `sudo tar -xzf /tmp/${pkg}.tar.gz -C /usr/local/bin ${pkg}\n` +
    `\nsudo mkdir -p /etc/fallbck ${dataDir} /var/log/fallbck\n` +
    `sudo chmod 0700 ${dataDir}\n` +
    `sudo curl -fsSL -o /etc/fallbck/${env} ${AGENT_WIZARD_RAW}/deploy/packaging/${env}\n` +
    `sudo chmod 0600 /etc/fallbck/${env}`;

  const service = `# systemd\n` +
    `sudo curl -fsSL -o /etc/systemd/system/${svc}.service ${AGENT_WIZARD_RAW}/deploy/systemd/${svc}.service\n` +
    `sudo systemctl daemon-reload\n\n` +
    `# OpenRC instead\n` +
    `sudo curl -fsSL -o /etc/init.d/${svc} ${AGENT_WIZARD_RAW}/deploy/openrc/${svc}.initd\n` +
    `sudo chmod 0755 /etc/init.d/${svc}\n` +
    `sudo curl -fsSL -o /etc/conf.d/${svc} ${AGENT_WIZARD_RAW}/deploy/openrc/${svc}.confd`;
  return { install, service };
}

function agentWizardSections(type, target, serverUrl, token) {
  const t = AGENT_WIZARD_TYPES[type] || AGENT_WIZARD_TYPES.files;
  const isDB = type === 'database';
  const sections = [];

  if (type === 'kubernetes') {
    sections.push({
      title: 'Install the Helm chart',
      text: 'Run this with a kubeconfig that is cluster-admin on the target cluster. The agent enrolls as k8s-<clusterName> and keeps its identity in a Secret in the fallbck namespace; helm upgrade never touches it.',
      code: `helm upgrade --install fallbck-k8s-agent \\\n  oci://oci.fi/helm/fallbck-k8s-agent \\\n  --namespace fallbck --create-namespace \\\n  --set server.url=${serverUrl} \\\n  --set clusterName=my-cluster \\\n  --set enrollment.key=${token}`,
      note: 'Private or self-signed server certificate: add --set-file server.caCert=ca.pem or, for testing only, --set server.insecureSkipVerify=true.'
    });
    sections.push({
      title: 'Verify',
      text: 'The cluster shows up on this page and on the Kubernetes page within a minute. Cluster jobs are created in the Kubernetes section; in-cluster database jobs on the Backup Jobs page.',
      code: 'kubectl -n fallbck get pods\nkubectl -n fallbck logs deploy/fallbck-k8s-agent'
    });
    return sections;
  }

  if (target === 'docker-container' && type === 'database') {
    sections.push({
      title: 'Run the agent as a container (tools flavour)',
      text: 'The tools flavour of the agent image ships pg_dump, mariadb-dump and mongodump. It backs up databases reachable over the network from the container; no host mounts are needed. The agent enrolls itself on first start with the key below; remove the key afterwards.',
      code: `services:\n  fallbck-agent:\n    image: oci.fi/fallbck/agent:tools\n    container_name: fallbck-agent\n    restart: unless-stopped\n    environment:\n      FALLBCK_AGENT_HOSTNAME: ${'$'}{HOSTNAME:-db-host}\n      FALLBCK_AGENT_SERVER_URL: ${serverUrl}\n      FALLBCK_AGENT_ENROLLMENT_KEY: ${token}\n      # credential profiles for jobs that leave the password blank:\n      # FALLBCK_AGENT_DB_PROFILE_MAIN_ENGINE: postgres\n      # FALLBCK_AGENT_DB_PROFILE_MAIN_USER: backup\n      # FALLBCK_AGENT_DB_PROFILE_MAIN_PASSWORD: secret\n    volumes:\n      - fallbck_agent_data:/var/lib/fallbck/agent\nvolumes:\n  fallbck_agent_data:`,
      note: 'Private or self-signed server certificate: mount the CA bundle and set FALLBCK_AGENT_SERVER_CA to its path, or FALLBCK_AGENT_INSECURE_SKIP_VERIFY=true for testing only.'
    });
    sections.push({
      title: 'Create the database job',
      text: 'The agent reports the client tools with its first heartbeat (about 30 seconds) and gets a DB tools badge on this page. Then create a job of type Database on the Backup Jobs page and assign it to this agent.',
      code: 'docker compose logs -f fallbck-agent'
    });
    return sections;
  }

  if (target === 'docker-container') {
    sections.push({
      title: 'Run the agent as a container',
      text: 'Save this as docker-compose.yml on the Docker host and start it with docker compose up -d. The agent enrolls itself on first start with the key below and keeps its identity in the fallbck_agent_data volume; remove the key afterwards. FALLBCK_AGENT_HOSTNAME names the agent and its snapshot group (host/<hostname>-docker), so set it to the host\'s real name rather than the container id.',
      code: `services:\n  fallbck-agent:\n    image: oci.fi/fallbck/agent:latest\n    container_name: fallbck-agent\n    user: "0:0"\n    restart: unless-stopped\n    environment:\n      FALLBCK_AGENT_HOSTNAME: ${'$'}{HOSTNAME:-docker-host}\n      FALLBCK_AGENT_SERVER_URL: ${serverUrl}\n      FALLBCK_AGENT_ENROLLMENT_KEY: ${token}\n      FALLBCK_AGENT_DOCKER_VOLUME_ACCESS: auto\n    volumes:\n      - fallbck_agent_data:/var/lib/fallbck/agent\n      - /var/run/docker.sock:/var/run/docker.sock\n      - /var/lib/docker/volumes:/var/lib/docker/volumes:ro\n      - /etc/docker:/etc/docker:ro\n      # compose project directories, so their config files can be archived:\n      - /opt/compose:/opt/compose:ro\nvolumes:\n  fallbck_agent_data:`,
      note: 'Without the /var/lib/docker/volumes mount the agent reads volumes through short-lived helper containers instead (slower, needs spool space). Private or self-signed server certificate: mount the CA bundle and set FALLBCK_AGENT_SERVER_CA to its path, or FALLBCK_AGENT_INSECURE_SKIP_VERIFY=true for testing only.'
    });
    sections.push({
      title: 'Create the Docker host job',
      text: 'The agent reports a reachable Docker daemon with its first heartbeat (about 30 seconds). Then create a job of type Docker host on the Backup Jobs page. Label containers fallbck.io/pause=true to pause them while their volumes are copied, and fallbck.io/skip=true on containers or volumes to leave them out.',
      code: 'docker compose logs -f fallbck-agent'
    });
    return sections;
  }

  if (target === 'windows') {
    sections.push({
      title: 'Install and enroll from an elevated PowerShell',
      text: 'Downloads the MSI from the latest GitHub release, installs the fallbck-agent Windows service and enrolls it with this server.',
      code: `& ([scriptblock]::Create((iwr -useb ${serverUrl}/install-agent.ps1).Content)) -Token ${token}`,
      note: 'Private or self-signed server certificate: add -CaCert C:\\path\\to\\ca.pem. An already downloaded installer can be passed with -MsiPath.'
    });
    sections.push({
      title: 'Or install the MSI by hand',
      text: `Download fallbck-agent_Windows_x86_64.msi from ${AGENT_WIZARD_RELEASES}/latest. Double-click it and enter the server URL and enrollment key below when asked; the installer enrolls the agent and starts the service. For an unattended install pass them on the command line instead:`,
      code: `# Server URL:      ${serverUrl}\n# Enrollment key:  ${token}\n\nmsiexec /i fallbck-agent_Windows_x86_64.msi /qn /norestart SERVER_URL=${serverUrl} TOKEN=${token}`
    });
    sections.push({
      title: 'Verify',
      text: 'State, caches and logs live in %ProgramData%\\fallbck\\agent. Backup paths are Windows paths (C:\\Users, D:\\data or a whole volume C:\\); every run first takes a Volume Shadow Copy.',
      code: '& "$env:ProgramFiles\\FallBCK\\fallbck-agent.exe" service status'
    });
    return sections;
  }

  // Linux: package (or manual install), client tools for the database agent,
  // enrollment through the served helper script (or by hand), then verify.
  const pkg = t.pkg;
  const svc = t.service;
  const sudo = target === 'proxmox' || target === 'alpine' ? '' : 'sudo ';

  if (target === 'linux-other') {
    const m = agentWizardManualLinux(type, pkg, svc);
    sections.push({
      title: 'Download the binary and the configuration template',
      text: `Releases are published at ${AGENT_WIZARD_RELEASES}. The archive holds the static ${pkg} binary; the environment template and service units come from the repository.`,
      code: m.install
    });
    sections.push({
      title: 'Create the service',
      text: 'Pick the init system of the host. The unit runs the agent from its state directory and reads the environment template.',
      code: m.service
    });
  } else {
    sections.push({
      title: target === 'proxmox' ? 'Add the package repository and install the agent (as root on the node)' : 'Add the package repository and install the agent',
      code: agentWizardRepo(target, pkg)
    });
  }

  if (isDB) {
    const tools = {
      debian: 'sudo apt install postgresql-client mariadb-client',
      rhel: 'sudo yum install postgresql mariadb',
      alpine: 'apk add postgresql-client mariadb-client mongodb-tools',
      'linux-other': '# for example on Debian:\nsudo apt install postgresql-client mariadb-client'
    }[target];
    sections.push({
      title: 'Install the client tools for the engines you back up',
      text: 'The package does not ship them: pg_dump must be at least as new as the server, mysqldump/mariadb-dump (binary-log fetching also needs mysqlbinlog/mariadb-binlog, on Alpine from the mariadb package) and mongodump from mongodb-database-tools (MongoDB\'s own repository on Debian and RHEL).',
      code: tools
    });
  }

  const enroll = `curl -sSL ${serverUrl}/install-agent.sh | ${sudo}sh -s -- \\\n  --server ${serverUrl} \\\n  --token ${token}` + (isDB ? ' \\\n  --type database' : '');
  sections.push({
    title: 'Enroll the agent and start the service',
    text: isDB
      ? 'Enrolls the agent with this server, lists the detected client tools and enables the service. The agent reports the tools with its heartbeat, which is what allows database jobs on it. The token is single use and valid for 24 hours.'
      : 'Enrolls the installed agent with this server and enables the service. The token is single use and valid for 24 hours.',
    code: enroll,
    note: 'Private or self-signed server certificate: run the enroll command by hand below with --ca-cert <pem bundle>.'
  });

  const start = target === 'alpine'
    ? `rc-update add ${svc} default && rc-service ${svc} start`
    : `${sudo}systemctl enable --now ${svc}`;
  const manual = `${sudo}fallbck-agent enroll --server ${serverUrl} --token ${token}\n` + (isDB ? 'fallbck-agent tools\n' : '') + start;
  sections.push({ title: 'Or enroll by hand', code: manual });

  if (type === 'docker') {
    sections.push({
      title: 'Create the Docker host job',
      text: 'The agent runs as root, so it reads the Docker socket and /var/lib/docker/volumes directly. It reports a reachable daemon with its next heartbeat (about 30 seconds); then create a job of type Docker host on the Backup Jobs page. Label containers fallbck.io/pause=true to pause them while their volumes are copied, and fallbck.io/skip=true on containers or volumes to leave them out.'
    });
  } else if (type === 'proxmox') {
    sections.push({
      title: 'Create the Proxmox VE host job',
      text: 'The agent reports itself as a PVE host with its next heartbeat (about 30 seconds). Then create a job of type Proxmox VE host on the Backup Jobs page; it archives the node configuration into one pve.pxar snapshot per run. Guest disks are not part of it, keep vzdump to PBS for those.'
    });
  } else {
    sections.push({
      title: 'Verify',
      text: 'The host appears in the list above within a minute' + (isDB ? ', with a DB tools badge once the client tools were detected' : '') + '. Logs: ' + (target === 'alpine' ? '/var/log/fallbck/agent.log' : `journalctl -u ${svc}`) + '.'
    });
  }
  return sections;
}

// 6. Action Handlers for Target, Job, and Run Creation
function targetForm() { return document.getElementById('target-form'); }

function newTarget() {
  const form = targetForm();
  form.reset();
  form.dataset.targetId = '';
  document.getElementById('target-modal-title').innerText = 'Add Proxmox Backup Server Target';
  document.getElementById('target-submit').innerText = 'Save Target';
  const tok = document.getElementById('target-token');
  tok.required = true;
  tok.placeholder = 'user@pbs!fallbck:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx';
  document.getElementById('target-token-hint').innerText = 'Encrypted on the server. Agents never receive this token directly.';
  form.elements['tls_verify'].checked = true;
  openModal('modal-add-target');
}

async function editTarget(id) {
  try {
    const resp = await apiFetch(`/api/v1/targets/${id}`);
    if (!resp.ok) throw new Error('Failed to load target');
    const t = await resp.json();
    const form = targetForm();
    form.reset();
    form.dataset.targetId = t.id;
    form.elements['name'].value = t.name || '';
    form.elements['endpoint'].value = t.endpoint || '';
    form.elements['datastore'].value = t.datastore || '';
    form.elements['namespace'].value = t.namespace || '';
    form.elements['fingerprint'].value = t.fingerprint || '';
    form.elements['pxar_format'].value = t.pxar_format || 'v1';
    form.elements['tls_verify'].checked = !!t.tls_verify;
    const tok = document.getElementById('target-token');
    tok.value = '';
    tok.required = false;
    tok.placeholder = t.has_token ? 'leave blank to keep the current token' : 'no token stored — enter one';
    document.getElementById('target-token-hint').innerText = 'Leave blank to keep the stored token, or enter a new one to replace it.';
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
  const formData = new FormData(form);
  const id = form.dataset.targetId || '';

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
    const resp = await apiFetch(id ? `/api/v1/targets/${id}` : '/api/v1/targets', {
      method: id ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const errData = await resp.json();
      throw new Error(errData.error || 'Failed to save target');
    }

    showToast(id ? 'Backup target updated' : 'Backup target added successfully!', 'success');
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
  const isPVE = type === 'pve';
  const isDocker = type === 'docker';
  const fs = document.getElementById('job-fs-fields');
  const dbf = document.getElementById('job-db-fields');
  const pve = document.getElementById('job-pve-fields');
  const dock = document.getElementById('job-docker-fields');
  fs.hidden = isDB || isPVE || isDocker; fs.disabled = isDB || isPVE || isDocker;
  dbf.hidden = !isDB; dbf.disabled = !isDB;
  pve.hidden = !isPVE; pve.disabled = !isPVE;
  dock.hidden = !isDocker; dock.disabled = !isDocker;
  const sel = form.elements['agent_id'];
  let keep = false;
  for (const opt of sel.options) {
    if (!opt.value) continue;
    const agentType = opt.dataset.agentType || 'filesystem';
    // Database jobs may also run on a kubernetes agent (dumped from a pod in the
    // cluster); Proxmox VE jobs need the filesystem agent installed on a PVE node
    let match = agentType === type;
    if (type === 'database') match = match || agentType === 'kubernetes' || (agentType === 'filesystem' && opt.dataset.db === 'true');
    if (type === 'pve') match = agentType === 'filesystem' && opt.dataset.pve === 'true';
    if (type === 'docker') match = agentType === 'filesystem' && opt.dataset.docker === 'true';
    opt.hidden = !match; opt.disabled = !match;
    if (match && opt.selected) keep = true;
  }
  if (!keep) sel.value = '';
  setDBEngine(form.elements['db_engine'].value);
  updateDBTarget();
}

// A database job on a kubernetes agent needs the in-cluster target settings; the
// agent-side credential profile and TLS files do not apply there
function selectedAgentIsK8s() {
  const sel = jobForm().elements['agent_id'];
  const opt = sel.options[sel.selectedIndex];
  return !!(opt && opt.value && opt.dataset.agentType === 'kubernetes');
}

function updateDBTarget() {
  const form = jobForm();
  const k8s = selectedAgentIsK8s() && form.elements['job_type'].value === 'database';
  const block = document.getElementById('db-k8s-fields');
  block.hidden = !k8s;
  block.querySelectorAll('input').forEach(c => { c.disabled = !k8s; });
  form.elements['db_k8s_namespace'].required = k8s;
  form.elements['db_profile'].disabled = k8s;
  form.elements['db_tls_ca_file'].disabled = k8s;
  document.getElementById('db-host-label').innerText = k8s ? 'Host (optional when a Service is given)' : 'Host (or unix socket path)';
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
      document.getElementById('db-password-hint').hidden = !dc.has_password;
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
      const k8s = dc.kubernetes || {};
      form.elements['db_k8s_namespace'].value = k8s.namespace || '';
      form.elements['db_k8s_service'].value = k8s.service || '';
      form.elements['db_k8s_secret'].value = k8s.secret_name || '';
      form.elements['db_k8s_password_key'].value = k8s.password_key || '';
      form.elements['db_k8s_user_key'].value = k8s.user_key || '';
      form.elements['db_k8s_tools_image'].value = k8s.tools_image || '';
    }
    setJobType(jobType);
    form.elements['agent_id'].value = job.agent_id || '';
    updateDBTarget();
    form.elements['schedule_cron'].value = job.schedule_cron || '';
    form.elements['direct_pbs'].checked = !!job.direct_pbs;
    form.elements['enabled'].checked = !!job.enabled;
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
    enabled: formData.get('enabled') === 'on',
    direct_pbs: formData.get('direct_pbs') === 'on',
    job_type: formData.get('job_type') || 'filesystem'
  };

  if (payload.job_type === 'pve') {
    payload.backup_paths = [];
    payload.exclude_paths = [];
    const lines = v => (formData.get(v) || '').split('\n').map(p => p.trim()).filter(p => p.length > 0);
    payload.pve_config = {
      data_paths: lines('pve_data_paths'),
      exclude_paths: lines('pve_exclude_paths'),
      include_root_home: formData.get('pve_include_root_home') === 'on',
      include_guest_images: formData.get('pve_include_guest_images') === 'on'
    };
  }

  if (payload.job_type === 'docker') {
    payload.backup_paths = [];
    payload.exclude_paths = [];
    const lines = v => (formData.get(v) || '').split('\n').map(p => p.trim()).filter(p => p.length > 0);
    payload.docker_config = {
      exclude_containers: lines('docker_exclude_containers'),
      exclude_volumes: lines('docker_exclude_volumes'),
      pause_containers: lines('docker_pause_containers'),
      exclude_paths: lines('docker_exclude_paths'),
      host_paths: lines('docker_host_paths'),
      images: formData.get('docker_images') || 'refs',
      include_unused_volumes: formData.get('docker_include_unused_volumes') === 'on',
      include_stopped: formData.get('docker_include_stopped') === 'on'
    };
  }

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
    if (selectedAgentIsK8s()) {
      dc.profile = '';
      dc.tls.ca_file = '';
      dc.kubernetes = {
        namespace: (formData.get('db_k8s_namespace') || '').trim(),
        service: (formData.get('db_k8s_service') || '').trim(),
        secret_name: (formData.get('db_k8s_secret') || '').trim(),
        password_key: (formData.get('db_k8s_password_key') || '').trim(),
        user_key: (formData.get('db_k8s_user_key') || '').trim(),
        tools_image: (formData.get('db_k8s_tools_image') || '').trim()
      };
    }
    if (engine === 'postgres') {
      dc.postgres = { mode: formData.get('pg_mode'), format: formData.get('pg_format'), role_passwords: formData.get('pg_role_passwords'), globals: formData.get('pg_globals') === 'on' };
    } else if (engine === 'mysql') {
      dc.mysql = { single_transaction: formData.get('my_single_transaction') === 'on', include_binlogs: formData.get('my_include_binlogs') === 'on', per_database: formData.get('my_per_database') === 'on' };
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
