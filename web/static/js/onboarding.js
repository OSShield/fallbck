// FallBCK onboarding page: install an agent, wait for its enrollment, then create
// backup jobs for it. Uses the shared form helpers from app.js (setJobTypeIn,
// buildJobPayload, buildK8sPayload, saveJob, saveTarget, cloneTarget, triggerJob).

// Agent installation instructions (moved from the Agents page wizard)

const AGENT_WIZARD_TYPES = {
  files:      { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  proxmox:    { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  docker:     { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  m365:       { label: 'filesystem agent', pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  database:   { label: 'database agent',   pkg: 'fallbck-agent',    service: 'fallbck-agent' },
  kubernetes: { label: 'Kubernetes agent' }
};









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
        `curl -fsSL https://deb.osshield.eu/key | ${sudo}gpg --dearmor -o /etc/apt/keyrings/osshield-eu.gpg\n` +
        `echo "deb [signed-by=/etc/apt/keyrings/osshield-eu.gpg] https://deb.osshield.eu all main" | ${sudo}tee /etc/apt/sources.list.d/osshield-eu.list\n` +
        `${sudo}apt update\n${sudo}apt install ${pkg}`;
    case 'rhel':
      return `sudo tee /etc/yum.repos.d/osshield-eu.repo <<'EOF'\n[osshield-eu]\nname=osshield.eu\nbaseurl=https://rpm.osshield.eu\nenabled=1\ngpgcheck=1\ngpgkey=https://rpm.osshield.eu/key\nEOF\n` +
        `sudo rpm --import https://rpm.osshield.eu/key\nsudo yum install ${pkg}`;
    case 'alpine':
      return `apk update\napk add curl\ncd /etc/apk/keys && curl -JO https://alpine.osshield.eu/key\n` +
        `echo "https://alpine.osshield.eu/all" >> /etc/apk/repositories\napk update\napk add ${pkg}`;
  }
  return '';
}

// Manual install from the GitHub release for distributions without a package:
// binary, state directories, environment template and a service unit.
function agentWizardManualLinux(pkg, svc) {
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
      code: `helm upgrade --install fallbck-k8s-agent \\\n  oci://cr.osshield.eu/helm/fallbck-k8s-agent \\\n  --namespace fallbck --create-namespace \\\n  --set server.url=${serverUrl} \\\n  --set clusterName=my-cluster \\\n  --set enrollment.key=${token}`,
      note: 'Private or self-signed server certificate: add --set-file server.caCert=ca.pem or, for testing only, --set server.insecureSkipVerify=true.'
    });
    sections.push({
      title: 'Verify',
      text: 'The agent enrolls within a minute. The next step waits for it and then sets up the cluster backup; in-cluster database jobs can be added the same way afterwards.',
      code: 'kubectl -n fallbck get pods\nkubectl -n fallbck logs deploy/fallbck-k8s-agent'
    });
    return sections;
  }

  if (target === 'docker-container' && type === 'database') {
    sections.push({
      title: 'Run the agent as a container (tools flavour)',
      text: 'The tools flavour of the agent image ships pg_dump, mariadb-dump and mongodump. It backs up databases reachable over the network from the container; no host mounts are needed. The agent enrolls itself on first start with the key below; remove the key afterwards.',
      code: `services:\n  fallbck-agent:\n    image: cr.osshield.eu/fallbck/agent:tools\n    container_name: fallbck-agent\n    restart: unless-stopped\n    environment:\n      FALLBCK_AGENT_HOSTNAME: ${'$'}{HOSTNAME:-db-host}\n      FALLBCK_AGENT_SERVER_URL: ${serverUrl}\n      FALLBCK_AGENT_ENROLLMENT_KEY: ${token}\n      # credential profiles for jobs that leave the password blank:\n      # FALLBCK_AGENT_DB_PROFILE_MAIN_ENGINE: postgres\n      # FALLBCK_AGENT_DB_PROFILE_MAIN_USER: backup\n      # FALLBCK_AGENT_DB_PROFILE_MAIN_PASSWORD: secret\n    volumes:\n      - fallbck_agent_data:/var/lib/fallbck/agent\nvolumes:\n  fallbck_agent_data:`,
      note: 'Private or self-signed server certificate: mount the CA bundle and set FALLBCK_AGENT_SERVER_CA to its path, or FALLBCK_AGENT_INSECURE_SKIP_VERIFY=true for testing only.'
    });
    sections.push({
      title: 'What happens next',
      text: 'The agent reports the client tools with its first heartbeat (about 30 seconds) and gets a DB tools badge on the Agents page. The next step waits for that and then sets up the Database job.',
      code: 'docker compose logs -f fallbck-agent'
    });
    return sections;
  }

  if (target === 'docker-container') {
    sections.push({
      title: 'Run the agent as a container',
      text: 'Save this as docker-compose.yml on the Docker host and start it with docker compose up -d. The agent enrolls itself on first start with the key below and keeps its identity in the fallbck_agent_data volume; remove the key afterwards. FALLBCK_AGENT_HOSTNAME names the agent and its snapshot group (host/<hostname>-docker), so set it to the host\'s real name rather than the container id.',
      code: `services:\n  fallbck-agent:\n    image: cr.osshield.eu/fallbck/agent:latest\n    container_name: fallbck-agent\n    user: "0:0"\n    restart: unless-stopped\n    environment:\n      FALLBCK_AGENT_HOSTNAME: ${'$'}{HOSTNAME:-docker-host}\n      FALLBCK_AGENT_SERVER_URL: ${serverUrl}\n      FALLBCK_AGENT_ENROLLMENT_KEY: ${token}\n      FALLBCK_AGENT_DOCKER_VOLUME_ACCESS: auto\n    volumes:\n      - fallbck_agent_data:/var/lib/fallbck/agent\n      - /var/run/docker.sock:/var/run/docker.sock\n      - /var/lib/docker/volumes:/var/lib/docker/volumes:ro\n      - /etc/docker:/etc/docker:ro\n      # compose project directories, so their config files can be archived:\n      - /opt/compose:/opt/compose:ro\nvolumes:\n  fallbck_agent_data:`,
      note: 'Without the /var/lib/docker/volumes mount the agent reads volumes through short-lived helper containers instead (slower, needs spool space). Private or self-signed server certificate: mount the CA bundle and set FALLBCK_AGENT_SERVER_CA to its path, or FALLBCK_AGENT_INSECURE_SKIP_VERIFY=true for testing only.'
    });
    sections.push({
      title: 'What happens next',
      text: 'The agent reports a reachable Docker daemon with its first heartbeat (about 30 seconds). The next step waits for that and then sets up the Docker host job. Label containers fallbck.io/pause=true to pause them while their volumes are copied, and fallbck.io/skip=true on containers or volumes to leave them out.',
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
    if (type === 'database') {
      sections.push({
        title: 'SQL Server access',
        text: 'SQL Server needs no client tools: the agent talks to it directly and reports the mssql engine with its first heartbeat. The service runs as LocalSystem, so for Windows integrated authentication give NT AUTHORITY\\SYSTEM a login with backup rights (or use a SQL login on the job instead). SQL Server writes its backup files into the instance\'s default backup directory, where the agent picks them up.',
        code: "CREATE LOGIN [NT AUTHORITY\\SYSTEM] FROM WINDOWS;  -- usually exists already\nALTER SERVER ROLE [sysadmin] ADD MEMBER [NT AUTHORITY\\SYSTEM];  -- or db_backupoperator in every database"
      });
    }
    sections.push({
      title: 'Or install with winget',
      text: 'Adds the OSShield winget source once, then installs the agent from it. Winget runs the MSI silently, so the server URL and enrollment key go in as MSI properties:',
      code: `winget source add --name "osshield" --arg "https://win.osshield.eu" --type "Microsoft.Rest"\nwinget source update\nwinget install --source osshield OSShield.FallbckAgent --custom "SERVER_URL=${serverUrl} TOKEN=${token}"`,
      note: 'Later upgrades: winget upgrade --source osshield OSShield.FallbckAgent.'
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
    const m = agentWizardManualLinux(pkg, svc);
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
      title: 'What happens next',
      text: 'The agent runs as root, so it reads the Docker socket and /var/lib/docker/volumes directly. It reports a reachable daemon with its next heartbeat (about 30 seconds); the next step waits for that and then sets up the Docker host job. Label containers fallbck.io/pause=true to pause them while their volumes are copied, and fallbck.io/skip=true on containers or volumes to leave them out.'
    });
  } else if (type === 'proxmox') {
    sections.push({
      title: 'What happens next',
      text: 'The agent reports itself as a PVE host with its next heartbeat (about 30 seconds). The next step waits for that and then sets up the Proxmox VE host job; it archives the node configuration into one pve.pxar snapshot per run. Guest disks are not part of it, keep vzdump to PBS for those.'
    });
  } else {
    sections.push({
      title: 'Verify',
      text: 'The host appears in the list above within a minute' + (isDB ? ', with a DB tools badge once the client tools were detected' : '') + '. Logs: ' + (target === 'alpine' ? '/var/log/fallbck/agent.log' : `journalctl -u ${svc}`) + '.'
    });
  }
  return sections;
}

// ---- Onboarding state machine --------------------------------------------------
// Phase A (steps 1-4) installs and waits for an agent, phase B (steps 5-9) creates
// backup jobs for it and repeats from step 5. Identities live in the URL so a reload
// resumes: token (enrollment token id, step 4), agent (agent id, phase B), jobs
// (created job ids, summary). Typed-in form values are not preserved.

const OB_ORDER = ['0', 'existing', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'summary'];
const OB_POLL_MS = 3000;
const OB_HINT_AFTER_MS = 90000;

const ob = {
  step: '0', start: '', type: '', platform: '', tokenId: '', token: '', agentId: '', agent: null,
  backupType: '', targetId: '', targetAutoPicked: false, jobs: [],
  pollTimer: null, waitStarted: 0
};

// Capability the onboarding type needs before backups of that kind can be created
const OB_TYPE_NEEDS = { database: 'db_tools', proxmox: 'pve_host', docker: 'docker_host' };
// Default backup type per onboarding type
const OB_TYPE_BACKUP = { files: 'filesystem', database: 'database', proxmox: 'pve', docker: 'docker', m365: 'm365', kubernetes: 'kubernetes' };

document.addEventListener('DOMContentLoaded', obInit);

async function obInit() {
  const q = new URLSearchParams(window.location.search);
  ob.type = q.get('type') || '';
  ob.platform = q.get('platform') || '';
  ob.tokenId = q.get('token') || '';
  ob.agentId = q.get('agent') || '';
  ob.jobs = (q.get('jobs') || '').split(',').filter(Boolean).map(id => ({ id }));
  const step = q.get('step') || '';
  obMarkSelected('type', ob.type);
  obMarkSelected('platform', ob.platform);
  if (ob.agentId) {
    await obLoadAgent();
    if (!ob.agent) {
      showToast('The agent from the link no longer exists', 'error');
      ob.agentId = '';
      ob.step = '0';
    } else if (ob.jobs.length) {
      await obLoadJobs();
      ob.step = 'summary';
    } else {
      ob.step = OB_ORDER.includes(step) && Number(step) >= 5 ? step : '5';
      if (ob.step === '6' || ob.step === '7' || ob.step === '8' || ob.step === '9') {
        // Form contents are not in the URL: restart the backup at its type step
        ob.step = '5';
      }
    }
  } else if (ob.tokenId) {
    ob.step = '4';
  } else if (ob.type && ob.platform && step === '3') {
    ob.step = '3';
  } else if (ob.type && step === '2') {
    ob.step = '2';
  } else if (step === '1' || step === 'existing') {
    ob.step = step;
    ob.start = step === '1' ? 'new' : 'existing';
    obMarkSelected('start', ob.start);
  } else {
    ob.step = '0';
  }
  obRender();
}

function obSetURL() {
  const q = new URLSearchParams();
  q.set('step', ob.step);
  if (ob.type) q.set('type', ob.type);
  if (ob.platform) q.set('platform', ob.platform);
  if (ob.tokenId && !ob.agentId) q.set('token', ob.tokenId);
  if (ob.agentId) q.set('agent', ob.agentId);
  if (ob.jobs.length) q.set('jobs', ob.jobs.map(j => j.id).join(','));
  history.replaceState(null, '', window.location.pathname + '?' + q.toString());
}

function obMarkSelected(kind, value) {
  document.querySelectorAll(`.wizard-option[data-kind="${kind}"]`).forEach(o => o.classList.toggle('selected', !!value && o.dataset.value === value));
}

function obSelect(el) {
  const kind = el.dataset.kind, value = el.dataset.value;
  if (el.classList.contains('ob-disabled')) return;
  switch (kind) {
    case 'start':
      ob.start = value;
      break;
    case 'agent':
      ob.agentId = value;
      break;
    case 'type':
      if (ob.type !== value) ob.platform = '';
      ob.type = value;
      break;
    case 'platform':
      ob.platform = value;
      break;
    case 'backup':
      ob.backupType = value;
      break;
    case 'target':
      if (value === '__new') {
        obShowNewTarget();
        return;
      }
      ob.targetId = value;
      ob.targetAutoPicked = false;
      obHideTargetForms();
      break;
  }
  obMarkSelected(kind, value);
  obUpdateFooter();
  // Picking a card is the answer: advance, unless the footer gate (e.g. key export) holds
  if (!document.getElementById('ob-next').disabled) obNext();
}

function obKey(event, el) {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    obSelect(el);
  }
}

function obNext() {
  switch (ob.step) {
    case '0': if (!ob.start) return; ob.step = ob.start === 'existing' ? 'existing' : '1'; break;
    case 'existing': if (!ob.agentId) return; obUseExisting(); return;
    case '1': if (!ob.type) return; ob.step = '2'; break;
    case '2': if (!ob.platform) return; ob.step = '3'; break;
    case '3': ob.step = '4'; break;
    case '4': if (!ob.agentId) return; ob.step = '5'; break;
    case '5':
      if (!ob.backupType) return;
      ob.step = '6';
      // One target and nothing chosen: take it and skip the step
      if (!ob.targetId) {
        const cards = obTargetCards();
        if (cards.length === 1) {
          ob.targetId = cards[0].dataset.value;
          ob.targetAutoPicked = true;
          obMarkSelected('target', ob.targetId);
          ob.step = '7';
        }
      }
      break;
    case '6': if (!ob.targetId) return; ob.step = '7'; break;
    case '7': {
      const form = document.getElementById('job-form');
      if (!form.reportValidity()) return;
      ob.step = '8';
      break;
    }
    case '8': {
      const form = document.getElementById('job-form');
      if (!form.reportValidity()) return;
      ob.step = '9';
      break;
    }
    case '9': obCreateJob(); return;
  }
  obRender();
}

function obBack() {
  const prev = { 'existing': '0', '1': '0', '2': '1', '3': '2', '4': '3', '5': ob.tokenId ? '4' : 'existing', '6': '5', '7': ob.targetAutoPicked ? '5' : '6', '8': '7', '9': '8', 'summary': '5' };
  const p = prev[ob.step];
  if (!p) return;
  if (ob.step === 'existing' || (ob.step === '5' && !ob.tokenId)) { ob.agentId = ''; ob.agent = null; obMarkSelected('agent', ''); }
  if (ob.step === '7' && ob.targetAutoPicked) { ob.targetId = ''; ob.targetAutoPicked = false; obMarkSelected('target', ''); }
  ob.step = p;
  obRender();
}

function obRender() {
  obStopWaiting();
  document.querySelectorAll('#onboarding .wizard-page').forEach(p => p.classList.toggle('active', p.dataset.step === ob.step));
  const n = ob.step === 'summary' ? 10 : ob.step === 'existing' ? 0 : Number(ob.step);
  document.querySelectorAll('#onboarding .wizard-progress-step').forEach(p => {
    const s = Number(p.dataset.step);
    p.classList.toggle('active', s === n);
    p.classList.toggle('done', s < n);
  });
  switch (ob.step) {
    case '2': obRenderPlatforms(); break;
    case '3': obRenderInstructions(); break;
    case '4': obStartWaiting(); break;
    case '5': obRenderBackupTypes(); break;
    case '6': obRenderTargets(); break;
    case '7': obRenderDetails(); break;
    case '8': break;
    case '9': obRenderReview(); break;
    case 'summary': obRenderSummary(); break;
  }
  obUpdateFooter();
  obSetURL();
}

function obUpdateFooter() {
  const back = document.getElementById('ob-back');
  const next = document.getElementById('ob-next');
  back.hidden = ob.step === '0' || ob.step === 'summary';
  next.hidden = ob.step === 'summary';
  let label = 'Next', ok = true;
  switch (ob.step) {
    case '0': ok = !!ob.start; break;
    case 'existing': label = 'Continue'; ok = !!ob.agentId; break;
    case '1': ok = !!ob.type; break;
    case '2': ok = !!ob.platform; break;
    case '3': label = 'I ran the commands'; break;
    case '4': label = 'Continue'; ok = !!ob.agentId; break;
    case '5': ok = !!ob.backupType; break;
    case '6': ok = !!ob.targetId && !(ob.pendingKeyTarget && ob.pendingKeyTarget === ob.targetId); break;
    case '9': label = 'Create backup job'; break;
  }
  next.innerText = label;
  next.disabled = !ok;
}

// ---- Phase A -------------------------------------------------------------------

function obRenderPlatforms() {
  document.getElementById('ob-type-label').innerText = (AGENT_WIZARD_TYPES[ob.type] || {}).label || 'agent';
  const options = Array.from(document.querySelectorAll('#ob-platform-options .wizard-option'));
  const visible = options.filter(o => o.dataset.types.split(',').includes(ob.type));
  options.forEach(o => { o.hidden = !visible.includes(o); });
  if (visible.length === 1 && !ob.platform) ob.platform = visible[0].dataset.value;
  obMarkSelected('platform', ob.platform);
}

// obLabels are the labels typed on the install step: they go on the token (so the
// agent enrolls with them) and prefill the new target and job forms
function obLabels() {
  const el = document.getElementById('ob-labels');
  return el ? parseLabels(el.value) : {};
}

function obPrefillLabels(labels) {
  for (const id of ['job-form', 'target-form']) {
    const f = document.getElementById(id);
    const el = f && f.querySelector('[name="labels"]');
    if (el && !el.value.trim()) el.value = formatLabels(labels);
  }
}

async function obMintToken() {
  const labels = obLabels();
  const resp = await apiFetch('/api/v1/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `Onboarding-${ob.type}-${new Date().toISOString().slice(0, 19)}`, max_uses: 1, expires_at: new Date(Date.now() + 24 * 3600 * 1000), labels })
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(err.error || 'Token generation failed');
  }
  obPrefillLabels(labels);
  const data = await resp.json();
  ob.tokenId = data.id;
  ob.token = data.raw_token;
}

async function obRenderInstructions() {
  const root = document.getElementById('ob-instructions');
  root.innerHTML = '';
  const wait = document.createElement('p');
  wait.className = 'wizard-lead';
  wait.innerText = 'Generating a single-use enrollment token…';
  root.appendChild(wait);
  try {
    if (!ob.token) await obMintToken();
  } catch (err) {
    wait.innerText = `Error: ${err.message}`;
    return;
  }
  if (ob.step !== '3') return;
  obSetURL();
  root.innerHTML = '';
  const sections = agentWizardSections(ob.type, ob.platform, window.location.origin, ob.token);
  sections.forEach((s, i) => root.appendChild(agentWizardSection(s, i)));
}

// obRemint mints a fresh token and shows the instructions again (after a reload the
// raw token is gone; the previous token stays valid until it expires or is used)
function obRemint(e) {
  e.preventDefault();
  ob.token = '';
  ob.tokenId = '';
  ob.step = ob.type && ob.platform ? '3' : '0';
  obRender();
}

function obStartWaiting() {
  obStopWaiting();
  ob.waitStarted = Date.now();
  document.getElementById('ob-agent-card').hidden = true;
  document.getElementById('ob-wait-hint').hidden = true;
  document.getElementById('ob-waiting').hidden = false;
  obPoll();
}

function obStopWaiting() {
  if (ob.pollTimer) { clearTimeout(ob.pollTimer); ob.pollTimer = null; }
}

async function obPoll() {
  if (ob.step !== '4') return;
  try {
    if (!ob.agentId) {
      if (!ob.tokenId) return;
      const resp = await apiFetch(`/api/v1/tokens/${ob.tokenId}`);
      if (resp.status === 404) {
        document.getElementById('ob-wait-hint').innerText = 'This token no longer exists (revoked or expired). Mint a new one below.';
        document.getElementById('ob-wait-hint').hidden = false;
        return;
      }
      if (resp.ok) {
        const t = await resp.json();
        if (t.agent_id) ob.agentId = t.agent_id;
      }
    }
    if (ob.agentId) {
      await obLoadAgent();
      obShowAgentCard();
      obUpdateFooter();
      obSetURL();
      const need = OB_TYPE_NEEDS[ob.type];
      if (!need || (ob.agent && ob.agent[need])) return; // done polling
    }
  } catch (err) {
    console.warn('onboarding poll', err);
  }
  if (Date.now() - ob.waitStarted > OB_HINT_AFTER_MS) {
    const hint = document.getElementById('ob-wait-hint');
    hint.innerText = ob.agentId
      ? 'The agent is enrolled but has not reported the capability this setup needs yet (it comes with the first heartbeat of the running service). Check that the service is started and, for databases, that the client tools are installed; you can continue and pick another backup type meanwhile.'
      : 'No enrollment yet. Check that the commands ran without errors on the host, that the service is started, and that the host can reach this server URL.';
    hint.hidden = false;
  }
  ob.pollTimer = setTimeout(obPoll, OB_POLL_MS);
}

async function obLoadAgent() {
  const resp = await apiFetch(`/api/v1/agents/${ob.agentId}`);
  ob.agent = resp.ok ? await resp.json() : null;
  if (ob.agent) obPrefillLabels(ob.agent.labels);
}

function obAgentCaps(a) {
  const caps = [];
  if (a.pve_host) caps.push('Proxmox VE');
  if (a.docker_host) caps.push('Docker');
  if ((a.db_engines || []).length) caps.push('DB: ' + a.db_engines.join(', '));
  else if (a.db_tools) caps.push('DB tools');
  return caps;
}

function obShowAgentCard() {
  const a = ob.agent;
  if (!a) return;
  document.getElementById('ob-waiting').hidden = true;
  const card = document.getElementById('ob-agent-card');
  const caps = obAgentCaps(a);
  card.innerHTML = '';
  const title = document.createElement('div');
  title.style.fontWeight = '600';
  title.innerText = `${a.hostname} enrolled`;
  const desc = document.createElement('div');
  desc.style.fontSize = '13px';
  desc.style.marginTop = '4px';
  desc.innerText = `${a.agent_type} agent, ${a.os}/${a.arch}, version ${a.version || '-'}, status ${a.status}` + (caps.length ? `, capabilities: ${caps.join(', ')}` : '');
  card.appendChild(title);
  card.appendChild(desc);
  const need = OB_TYPE_NEEDS[ob.type];
  if (need && !a[need]) {
    const w = document.createElement('div');
    w.className = 'wizard-note';
    w.style.marginTop = '6px';
    w.innerHTML = '<span class="ob-spinner"></span>Waiting for the agent to report ' + { db_tools: 'the database client tools', pve_host: 'that it runs on a Proxmox VE node', docker_host: 'a reachable Docker daemon' }[need] + ' (first heartbeat of the service)…';
    card.appendChild(w);
  }
  card.hidden = false;
}

async function obUseExisting() {
  if (!ob.agentId) return;
  ob.tokenId = '';
  ob.token = '';
  await obLoadAgent();
  if (!ob.agent) { showToast('Agent not found', 'error'); return; }
  ob.step = '5';
  obRender();
}

// ---- Phase B -------------------------------------------------------------------

function obBackupAvailable(kind) {
  const a = ob.agent || {};
  const t = a.agent_type || 'filesystem';
  switch (kind) {
    case 'filesystem': return t === 'filesystem';
    case 'database': return t === 'kubernetes' || (t === 'filesystem' && ((a.db_engines || []).length > 0 || a.db_tools));
    case 'pve': return t === 'filesystem' && a.pve_host;
    case 'docker': return t === 'filesystem' && a.docker_host;
    case 'm365': return t === 'filesystem'; // any agent with internet access
    case 'kubernetes': return t === 'kubernetes';
  }
  return false;
}

async function obRenderBackupTypes() {
  if (ob.agentId) await obLoadAgent(); // capabilities may have arrived since step 4
  document.getElementById('ob-agent-name').innerText = ob.agent ? ob.agent.hostname : 'the agent';
  const missing = [];
  document.querySelectorAll('#ob-backup-options .wizard-option').forEach(o => {
    const ok = obBackupAvailable(o.dataset.value);
    o.hidden = !ok;
    if (!ok && ob.agent && (ob.agent.agent_type || 'filesystem') === 'filesystem' && o.dataset.value !== 'kubernetes') missing.push(o.dataset.value);
  });
  if (!ob.backupType || !obBackupAvailable(ob.backupType)) {
    const wanted = OB_TYPE_BACKUP[ob.type];
    ob.backupType = wanted && obBackupAvailable(wanted) ? wanted : '';
    if (!ob.backupType) {
      const first = Array.from(document.querySelectorAll('#ob-backup-options .wizard-option')).find(o => !o.hidden);
      if (first) ob.backupType = first.dataset.value;
    }
  }
  obMarkSelected('backup', ob.backupType);
  const note = document.getElementById('ob-backup-note');
  const explain = { database: 'Database: install pg_dump / mariadb-dump / mongodump on the host; the agent reports them within a minute.', pve: 'Proxmox VE host: only for agents on a PVE node.', docker: 'Docker host: only for agents that can reach a Docker daemon.' };
  const lines = missing.map(m => explain[m]).filter(Boolean);
  note.innerText = lines.length ? 'Not offered for this agent yet: ' + lines.join(' ') : '';
  note.hidden = !lines.length;
  obUpdateFooter();
}

function obTargetCards() {
  return Array.from(document.querySelectorAll('#ob-target-options .wizard-option[data-kind="target"]')).filter(c => c.dataset.value !== '__new');
}

function obRenderTargets() {
  obHideTargetForms();
  obMarkSelected('target', ob.targetId);
}

function obHideTargetForms() {
  document.getElementById('ob-target-clone').hidden = true;
  document.getElementById('ob-target-new').hidden = true;
}

function obShowNewTarget() {
  obHideTargetForms();
  resetTargetForm(document.getElementById('target-form'));
  document.getElementById('ob-target-new').hidden = false;
}

function obShowClone(id, name, namespace) {
  obHideTargetForms();
  const form = document.getElementById('ob-clone-form');
  form.reset();
  form.dataset.targetId = id;
  document.getElementById('ob-clone-source').innerText = name + (namespace ? ` (namespace ${namespace})` : ' (root namespace)');
  form.elements['name'].value = name + '-';
  document.getElementById('ob-target-clone').hidden = false;
  form.elements['namespace'].focus();
}

// obAddTargetCard appends a card for a target created in this session and selects it
function obAddTargetCard(t) {
  const card = document.createElement('div');
  card.className = 'wizard-option';
  card.setAttribute('role', 'button');
  card.tabIndex = 0;
  card.dataset.kind = 'target';
  card.dataset.value = t.id;
  card.dataset.name = t.name;
  card.dataset.namespace = t.namespace || '';
  card.dataset.datastore = t.datastore || '';
  card.dataset.endpoint = t.endpoint || '';
  card.onclick = () => obSelect(card);
  card.onkeydown = (e) => obKey(e, card);
  const title = document.createElement('div');
  title.className = 'wizard-option-title';
  title.innerText = t.name;
  const desc = document.createElement('div');
  desc.className = 'wizard-option-desc';
  desc.innerText = `${t.endpoint}, datastore ${t.datastore}, ${t.namespace ? 'namespace ' + t.namespace : 'root namespace'}, pxar ${t.pxar_format || 'v1'}${t.encryption_mode === 'encrypt' ? ', encrypted' : ''}`;
  card.appendChild(title);
  card.appendChild(desc);
  if (t.encryption_mode === 'encrypt' && t.key_fingerprint) {
    // The key was just generated: nothing on this target is restorable without it,
    // so the flow does not continue until the key file has been downloaded
    ob.pendingKeyTarget = t.id;
    const gate = document.createElement('div');
    gate.className = 'ob-key-gate';
    gate.style.cssText = 'margin-top:10px;padding:10px 12px;border:1px solid var(--danger-text);border-radius:var(--radius-sm);font-size:13px;';
    gate.onclick = (e) => e.stopPropagation();
    gate.innerHTML = `<strong>Export the encryption key before continuing.</strong> Key <code style="font-family:var(--font-mono);font-size:11px;">${t.key_fingerprint}</code>.<div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap;"><input type="password" class="form-control" placeholder="passphrase for the key file (min 12)" style="max-width:280px;" autocomplete="new-password"><button type="button" class="btn btn-primary btn-sm">Export key file</button></div>`;
    const pass = gate.querySelector('input');
    gate.querySelector('button').onclick = () => exportTargetKey({ _target: t, elements: { key_passphrase: pass }, dataset: {}, querySelector: () => null, querySelectorAll: () => [] });
    card.appendChild(gate);
  }
  const newCard = document.querySelector('#ob-target-options .wizard-option[data-value="__new"]');
  newCard.parentElement.insertBefore(card, newCard);
  ob.targetId = t.id;
  ob.targetAutoPicked = false;
  obMarkSelected('target', t.id);
  obHideTargetForms();
  obUpdateFooter();
}

async function obCreateTarget(e) {
  e.preventDefault();
  const form = e.target;
  try {
    const t = await saveTarget(buildTargetPayload(form), '');
    showToast(`Target ${t.name} created`, 'success');
    obAddTargetCard(t);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function obCloneTarget(e) {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  try {
    const t = await cloneTarget(form.dataset.targetId, { name: fd.get('name'), namespace: fd.get('namespace') });
    showToast(`Target ${t.name} created`, 'success');
    obAddTargetCard(t);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function obRenderDetails() {
  const form = document.getElementById('job-form');
  const a = ob.agent || {};
  form.dataset.agentType = a.agent_type || 'filesystem';
  form.dataset.hostname = a.hostname || '';
  form.dataset.dbProfiles = ((a.inventory && a.inventory.profiles) || []).map(p => `${p.name}:${p.engine || ''}`).join(',');
  form.dataset.jobType = ob.backupType;
  form.elements['agent_id'].value = ob.agentId;
  form.elements['target_id'].value = ob.targetId;
  const hint = form.querySelector('#db-password-hint');
  if (hint) hint.hidden = true;
  setJobTypeIn(form, ob.backupType);
  if (ob.backupType === 'database') obLimitEngines(form, a);
  if (ob.backupType === 'kubernetes' && !form.elements['k8s_ns_exclude'].value) {
    form.elements['k8s_ns_exclude'].value = K8S_DEFAULT_NS_EXCLUDES.join('\n');
  }
  if (!form.elements['name'].value) {
    const label = { filesystem: 'files', database: 'databases', pve: 'PVE host', docker: 'Docker host', m365: 'Microsoft 365', kubernetes: 'cluster' }[ob.backupType] || 'backup';
    form.elements['name'].value = ob.backupType === 'm365' ? 'Microsoft 365' : `${a.hostname || 'host'} ${label}`;
  }
}

// obLimitEngines offers only the engines the fixed agent can back up: the ones a
// filesystem agent reported, or everything but SQL Server on a kubernetes agent
function obLimitEngines(form, agent) {
  const sel = form.elements['db_engine'];
  if (!sel) return;
  const engines = agent.db_engines || [];
  const k8s = (agent.agent_type || 'filesystem') === 'kubernetes';
  let first = '';
  for (const opt of sel.options) {
    const ok = k8s ? opt.value !== 'mssql' : (engines.length ? engines.includes(opt.value) : opt.value !== 'mssql');
    opt.disabled = !ok; opt.hidden = !ok;
    if (ok && !first) first = opt.value;
  }
  if (sel.selectedOptions[0] && sel.selectedOptions[0].disabled && first) sel.value = first;
  setDBEngine(sel.value, form);
}

function obPreset(cron) {
  document.getElementById('job-form').elements['schedule_cron'].value = cron;
}

function obPayload() {
  const form = document.getElementById('job-form');
  return ob.backupType === 'kubernetes' ? buildK8sPayload(form) : buildJobPayload(form);
}

function obRenderReview() {
  const p = obPayload();
  const target = obTargetCards().find(c => c.dataset.value === ob.targetId);
  const rows = [
    ['Agent', (ob.agent || {}).hostname || ob.agentId],
    ['Backup type', { filesystem: 'Files', database: 'Database', pve: 'Proxmox VE host', docker: 'Docker host', m365: 'Microsoft 365 tenant', kubernetes: 'Kubernetes cluster' }[p.job_type] || p.job_type],
    ['Job name', p.name],
    ['Target', target ? `${target.dataset.name} (${target.dataset.datastore}${target.dataset.namespace ? ', ' + target.dataset.namespace : ''})` : ob.targetId, ob.targetAutoPicked ? 'change' : ''],
  ];
  if (p.job_type === 'filesystem') rows.push(['Paths', p.backup_paths.join(', ')], ['Excludes', p.exclude_paths.join(', ') || '-']);
  if (p.job_type === 'database' && p.db_config.mssql) rows.push(['SQL Server mode', p.db_config.mssql.mode + (p.db_config.mssql.include_log ? ' + log' : '')]);
  if (p.job_type === 'database') rows.push(['Engine', p.db_config.engine], ['Host', p.db_config.host || (p.db_config.kubernetes ? p.db_config.kubernetes.service : '') || '-'], ['Databases', (p.db_config.databases || []).join(', ') || 'all']);
  if (p.job_type === 'pve') rows.push(['Data paths', (p.pve_config.data_paths || []).join(', ') || 'none']);
  if (p.job_type === 'docker') rows.push(['Host paths', (p.docker_config.host_paths || []).join(', ') || 'none'], ['Images', p.docker_config.images]);
  if (p.job_type === 'm365') {
    const mc = p.m365_config;
    const sel = document.getElementById('job-form').elements['m365_tenant_id'];
    const tenant = sel && sel.selectedOptions[0] ? sel.selectedOptions[0].dataset.name : mc.tenant_id;
    const wl = Object.keys(mc.workloads).filter(k => mc.workloads[k]);
    rows.push(['Tenant', tenant || '-'], ['Workloads', wl.join(', ') || 'none'],
      ['Users', mc.users.groups.length ? 'members of ' + mc.users.groups.join(', ') : (mc.users.include.length ? mc.users.include.join(', ') : 'all licensed' + (mc.users.shared ? ' + shared mailboxes' : ''))]);
  }
  if (p.job_type === 'kubernetes') rows.push(['Volumes', p.k8s_config.volumes.mode], ['Namespaces', (p.k8s_config.namespaces.include || []).join(', ') || 'all']);
  rows.push(['Schedule', p.schedule_cron ? `${p.schedule_cron} (${document.getElementById('onboarding').dataset.timezone})` : 'manual only'],
    ['Enabled', p.enabled ? 'yes' : 'no'], ['Direct PBS', p.direct_pbs ? 'yes' : 'no'], ['Retention', 'PBS datastore prune job']);
  const dl = document.getElementById('ob-review');
  dl.innerHTML = '';
  rows.forEach(([k, v, action]) => {
    const dt = document.createElement('dt'); dt.innerText = k;
    const dd = document.createElement('dd'); dd.innerText = v || '-';
    if (action === 'change') {
      const a = document.createElement('a');
      a.href = '#'; a.innerText = ' Change target';
      a.style.marginLeft = '8px';
      a.onclick = (e) => { e.preventDefault(); ob.targetAutoPicked = false; ob.step = '6'; obRender(); };
      dd.appendChild(a);
    }
    dl.appendChild(dt); dl.appendChild(dd);
  });
  document.getElementById('ob-review-error').hidden = true;
}

async function obCreateJob() {
  const next = document.getElementById('ob-next');
  next.disabled = true;
  try {
    const job = await saveJob(obPayload(), '');
    ob.jobs.push({ id: job.id, name: job.name, job_type: job.job_type, schedule_cron: job.schedule_cron, enabled: job.enabled });
    showToast(`Backup job ${job.name} created`, 'success');
    ob.step = 'summary';
    obRender();
  } catch (err) {
    const el = document.getElementById('ob-review-error');
    el.innerText = err.message;
    el.hidden = false;
    next.disabled = false;
  }
}

async function obLoadJobs() {
  const loaded = [];
  for (const j of ob.jobs) {
    try {
      const resp = await apiFetch(`/api/v1/jobs/${j.id}`);
      if (resp.ok) {
        const job = await resp.json();
        loaded.push({ id: job.id, name: job.name, job_type: job.job_type, schedule_cron: job.schedule_cron, enabled: job.enabled });
      }
    } catch (err) { /* dropped from the summary */ }
  }
  ob.jobs = loaded;
}

function obRenderSummary() {
  document.getElementById('ob-summary-agent').innerText = (ob.agent || {}).hostname || '';
  const root = document.getElementById('ob-summary-jobs');
  root.innerHTML = '';
  ob.jobs.forEach(j => {
    const row = document.createElement('div');
    row.className = 'ob-job';
    row.id = `ob-job-${j.id}`;
    const left = document.createElement('div');
    const name = document.createElement('div'); name.style.fontWeight = '600'; name.innerText = j.name;
    const meta = document.createElement('div'); meta.className = 'ob-run-status';
    meta.innerText = `${j.job_type}, ${j.schedule_cron ? 'schedule ' + j.schedule_cron : 'manual'}${j.enabled ? '' : ', disabled'}`;
    const status = document.createElement('div'); status.className = 'ob-run-status'; status.id = `ob-run-${j.id}`;
    left.appendChild(name); left.appendChild(meta); left.appendChild(status);
    const right = document.createElement('div');
    const run = document.createElement('button'); run.type = 'button'; run.className = 'btn btn-secondary btn-sm'; run.innerText = 'Run now';
    run.onclick = () => obRunNow(j.id, run);
    const edit = document.createElement('a'); edit.className = 'btn btn-secondary btn-sm'; edit.href = '/jobs'; edit.innerText = 'Jobs page'; edit.style.marginLeft = '6px';
    right.appendChild(run); right.appendChild(edit);
    row.appendChild(left); row.appendChild(right);
    root.appendChild(row);
  });
}

async function obRunNow(jobId, button) {
  button.disabled = true;
  const status = document.getElementById(`ob-run-${jobId}`);
  status.innerHTML = '<span class="ob-spinner"></span>Starting…';
  try {
    const run = await triggerJob(jobId);
    if (!run.id) throw new Error('The run id was not returned');
    window.location.href = `/runs/${run.id}`;
  } catch (err) {
    status.innerText = `Could not start: ${err.message}`;
    button.disabled = false;
  }
}

function obAddAnother() {
  const form = document.getElementById('job-form');
  form.reset();
  form.dataset.jobId = '';
  ob.backupType = '';
  ob.step = '5';
  obRender();
}

// obKeyExported lifts the key gate once the key file of the new target is downloaded
function obKeyExported(t) {
  if (ob.pendingKeyTarget !== t.id) return;
  ob.pendingKeyTarget = '';
  document.querySelectorAll('.ob-key-gate').forEach(g => { g.innerHTML = '<strong>Key file downloaded.</strong> Keep it and its passphrase away from the server.'; g.style.borderColor = 'var(--border)'; });
  obUpdateFooter();
}
