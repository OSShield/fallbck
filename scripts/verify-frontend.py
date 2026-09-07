#!/usr/bin/env python3
"""Exercise HTML mutations against deploy/compose.ui-test.yml only.

The test stack uses an isolated network and a disposable tmpfs database. It has
no connection to the developer's normal data. Leaves synthetic records for
browser inspection; `docker compose -f deploy/compose.ui-test.yml down -v` removes
this entire test environment. Never point this script at a real server.
"""
import datetime as dt
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = 'http://127.0.0.1:18081'
container = json.loads(subprocess.check_output(['docker', 'inspect', 'fallbck-ui-test-server-1']))[0]
assert container['Config']['Labels']['com.docker.compose.project'] == 'fallbck-ui-test'
assert 'FALLBCK_DB_URL=postgres://ui_test:ui_test_disposable@postgres:5432/ui_test?sslmode=disable' in container['Config']['Env']
network = json.loads(subprocess.check_output(['docker', 'network', 'inspect', 'fallbck-ui-test_default']))[0]
assert network['Internal'], 'Tests require an isolated network'


def request(path, data=None, *, api=False, expected=200, method=None):
    headers = {'HX-Request': 'true', 'X-Requested-With': 'fallbck', 'HX-Current-URL': BASE + '/dashboard'}
    body = None
    if data is not None:
        body = json.dumps(data).encode() if api else urllib.parse.urlencode(data).encode()
        headers['Content-Type'] = 'application/json' if api else 'application/x-www-form-urlencoded'
    try:
        response = urllib.request.urlopen(urllib.request.Request(BASE + path, body, headers, method=method), timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    text = response.read().decode()
    assert response.status == expected, (path, response.status, text[:300])
    return json.loads(text) if api else text, response.headers


class Form(HTMLParser):
    def __init__(self, text):
        super().__init__(); self.values = {}; self.current = None; self.option = None; self.first = True
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'input' and 'name' in a:
            if a.get('type') != 'checkbox' or 'checked' in a:
                self.values[a['name']] = a.get('value', 'on' if a.get('type') == 'checkbox' else '')
        if tag in ('textarea', 'select'):
            self.current = (tag, a.get('name')); self.first = True
            if self.current[1]: self.values[self.current[1]] = ''
        if tag == 'option' and self.current:
            if self.first or 'selected' in a: self.values[self.current[1]] = a.get('value', '')
            self.first = False
    def handle_data(self, text):
        if self.current and self.current[0] == 'textarea': self.values[self.current[1]] += text
    def handle_endtag(self, tag):
        if tag in ('textarea', 'select'): self.current = None


def form(resource, **values):
    markup, _ = request('/ui/' + resource + '/form')
    fields = Form(markup).values; fields.update(values); return fields


def raw_secret(markup):
    start = markup.index('id="generated-secret"')
    return html.unescape(markup[markup.index('>', start) + 1:markup.index('</pre>', start)])

suffix = uuid.uuid4().hex[:6]
name = lambda value: value + ' · verification ' + suffix
# Server validation must preserve the form and return escaped HTML, not JSON.
payload = form('targets', name=name('Archive'), endpoint='https://pbs.example.invalid:8007', datastore='test')
text, headers = request('/ui/targets/save', payload, expected=400)
assert headers['HX-Retarget'] == '#form-errors' and 'PBS API token' in text
payload['auth_token'] = 'test@pbs!disposable:not-a-real-credential'
_, headers = request('/ui/targets/save', payload)
assert json.loads(headers['HX-Location'])['path'] == '/targets'
targets, _ = request('/api/v1/targets', api=True)
target = next(t for t in targets if t['name'] == payload['name'])
assert target['has_token'] and 'auth_token_encrypted' not in target
edit, _ = request('/ui/targets/form?id=' + target['id'])
assert 'not-a-real-credential' not in edit
updated = Form(edit).values; updated['name'] = name('Archive west'); updated['auth_token'] = ''
request('/ui/targets/save?id=' + target['id'], updated)
updated_target, _ = request('/api/v1/targets/' + target['id'], api=True)
assert updated_target['has_token'] and updated_target['name'] == updated['name']
print('PASS target create, edit, validation and credential redaction')

agents = {}
for kind in ['filesystem', 'database', 'kubernetes']:
    response, headers = request('/ui/tokens/save', form('tokens', name=name(kind), max_uses='1', days='1'))
    token = raw_secret(response)
    assert headers['Cache-Control'] == 'no-store'
    agent, _ = request('/api/v1/agents/enroll', {'token':token, 'hostname':name({'filesystem':'archive-node-01','database':'db-primary-01','kubernetes':'cluster-north-01'}[kind]), 'agent_type':kind, 'os':'linux', 'arch':'arm64', 'version':'0.3.0'}, api=True, expected=201)
    agents[kind] = agent['agent_id']
    request('/ui/agents/' + agent['agent_id'] + '/debug-on', {})
    record, _ = request('/api/v1/agents/' + agent['agent_id'], api=True)
    assert record['debug_logging']
    request('/ui/agents/' + agent['agent_id'] + '/debug-off', {})
print('PASS enrollment and agent debug controls')

jobs = {}
for kind, engine in [('filesystem',''), ('database','postgres'), ('database','mysql'), ('database','mongodb'), ('kubernetes','')]:
    values = form('jobs', name=name(kind + (' / ' + engine if engine else '')), job_type=kind, agent_id=agents[kind], target_id=target['id'], backup_paths='/etc\n/srv/archive', schedule_cron='0 2 * * *')
    values.pop('enabled', None)
    values.update({'db_config.engine':engine, 'db_config.host':'db.example.invalid', 'db_config.password':'disposable-test-password', 'retention_policy.keep_yearly':'2'})
    request('/ui/jobs/save', values)
    records, _ = request('/api/v1/jobs', api=True)
    job = next(j for j in records if j['name'] == values['name'])
    jobs[kind + engine] = job
    markup, _ = request('/ui/jobs/form?id=' + job['id'])
    assert 'disposable-test-password' not in markup
    changed = Form(markup).values; changed['name'] += ' revised'
    request('/ui/jobs/save?id=' + job['id'], changed)
    result, _ = request('/api/v1/jobs/' + job['id'], api=True)
    assert result['name'] == changed['name'] and result['retention_policy']['keep_yearly'] == 2
    if kind == 'database': assert result['db_config']['has_password']
print('PASS filesystem, PostgreSQL, MySQL, MongoDB and Kubernetes job create/edit')
postgres_job = jobs['databasepostgres']
advanced, _ = request('/api/v1/jobs/' + postgres_job['id'], api=True)
advanced['db_config']['tls']['cert_file'] = '/etc/test-client.pem'
advanced['db_config']['postgres']['extra_dump_args'] = ['--no-owner']
request('/api/v1/jobs/' + postgres_job['id'], advanced, api=True, method='PUT')
markup, _ = request('/ui/jobs/form?id=' + postgres_job['id'])
changed = Form(markup).values
request('/ui/jobs/save?id=' + postgres_job['id'], changed)
advanced, _ = request('/api/v1/jobs/' + postgres_job['id'], api=True)
assert advanced['db_config']['tls']['cert_file'] == '/etc/test-client.pem'
assert advanced['db_config']['postgres']['extra_dump_args'] == ['--no-owner']
changed['db_config.clear_password'] = 'on'
request('/ui/jobs/save?id=' + postgres_job['id'], changed)
advanced, _ = request('/api/v1/jobs/' + postgres_job['id'], api=True)
assert not advanced['db_config'].get('has_password', False)
print('PASS preservation of advanced settings and explicit password clearing')


# Trigger and cancel only on the isolated network, with no agent worker running.
request('/ui/jobs/' + jobs['filesystem']['id'] + '/run', {})
runs, _ = request('/api/v1/runs', api=True)
active = next(r for r in runs if r['job_id'] == jobs['filesystem']['id'])
request('/ui/runs/' + active['id'] + '/cancel', {})
record, _ = request('/api/v1/runs/' + active['id'], api=True)
assert record['status'] in ('cancelled', 'cancelling')
print('PASS start and cancellation of a test-only run')

response, _ = request('/ui/apikeys/save', form('apikeys', name=name('Test integration'), days='1'))
assert raw_secret(response).startswith('fbk_')
keys, _ = request('/api/v1/apikeys', api=True)
key = next(k for k in keys if k['name'] == name('Test integration'))
request('/ui/apikeys/' + key['id'] + '/delete', {})
keys, _ = request('/api/v1/apikeys', api=True)
assert next(k for k in keys if k['id'] == key['id'])['revoked_at']
print('PASS API key creation and revocation')

# Exercise destructive actions only on disposable records created here.
response, _ = request('/ui/tokens/save', form('tokens', name=name('Revoke me'), days='1', max_uses='1'))
tokens, _ = request('/api/v1/tokens', api=True)
token_record = next(v for v in tokens if v['name'] == name('Revoke me'))
request('/ui/tokens/' + token_record['id'] + '/delete', {})
tokens, _ = request('/api/v1/tokens', api=True)
assert not any(v['id'] == token_record['id'] for v in tokens)
response, _ = request('/ui/tokens/save', form('tokens', name=name('Disposable enrollment'), days='1', max_uses='1'))
spare_agent, _ = request('/api/v1/agents/enroll', {'token':raw_secret(response), 'hostname':name('delete-me'), 'agent_type':'filesystem','os':'linux','arch':'arm64'}, api=True, expected=201)
request('/ui/agents/' + spare_agent['agent_id'] + '/delete', {})
request('/api/v1/agents/' + spare_agent['agent_id'], api=True, expected=404)
spare_target_payload = form('targets', name=name('Disposable target'), endpoint='https://unused.example.invalid', datastore='test', auth_token='test@pbs!unused:disposable')
request('/ui/targets/save', spare_target_payload)
targets, _ = request('/api/v1/targets', api=True)
spare_target = next(v for v in targets if v['name'] == name('Disposable target'))
spare_job_payload = form('jobs', name=name('Disposable job'), job_type='filesystem', agent_id=agents['filesystem'], target_id=spare_target['id'], backup_paths='/never-run')
spare_job_payload.pop('enabled', None)
request('/ui/jobs/save', spare_job_payload)
records, _ = request('/api/v1/jobs', api=True)
spare_job = next(v for v in records if v['name'] == name('Disposable job'))
request('/ui/jobs/' + spare_job['id'] + '/delete', {})
request('/api/v1/jobs/' + spare_job['id'], api=True, expected=404)
request('/ui/targets/' + spare_target['id'] + '/delete', {})
request('/api/v1/targets/' + spare_target['id'], api=True, expected=404)
print('PASS agent, target, job and enrollment-token deletion')

# Populate completed/failed/active records to exercise every server-rendered detail.
now = dt.datetime.now(dt.timezone.utc)
run_ids = []
manifest_cases = [
 ('filesystem', 'completed', {'type':'filesystem','format':'v1','paths':['/etc','/srv/archive'],'archives':[{'name':'root.pxar','kind':'pxar','size_bytes':1073741824,'chunks':256,'new_chunks':38,'reused_chunks':218,'dedup':6.7}]}),
 ('databasepostgres', 'completed', {'type':'database','manifest':{'engine':'postgres','server':{'host':'db-primary-01','port':5432,'version':'16.4'},'databases':[{'name':'accounts','file':'accounts.dump','format':'custom','size_bytes':4194304,'duration_ms':1840}],'postgres':{'mode':'dump','wal_lsn':'0/7000060'},'restore':{'summary':'Restore the logical dump on a compatible PostgreSQL server.','commands':['pg_restore --dbname=accounts accounts.dump']}}}),
 ('kubernetes', 'failed', {'type':'kubernetes','manifest':{'generator':{'cluster':'north'},'kubernetes':{'server_version':'v1.34.0','snapshot_crd':True},'resources':{'counts':{'apps/deployments':24,'core/services':18},'namespaces':['production','archive'],'secrets_included':True},'volumes':[{'namespace':'production','pvc':'postgres-data','status':'completed','mode':'snapshot','consistency':'csi-snapshot','bytes_uploaded':824246272,'snapshot_id':'host/k8s-north-pvc-production-postgres-data/2026-09-07T02:00:00Z'},{'namespace':'archive','pvc':'media-data','status':'failed','mode':'live','consistency':'crash-consistent-live','error':'Verification fixture: snapshot class unavailable'}],'warnings':['One persistent volume did not complete.'],'restore':{'summary':'Restore resources, then data into the recreated PVCs.','commands':['kubectl apply -f resources/']}}}),
 ('kubernetes', 'running', None),
]
def literal(value): return "'" + str(value).replace("'", "''") + "'"
for kind, status, details in manifest_cases:
    run_id = str(uuid.uuid4()); run_ids.append(run_id); job = jobs[kind]
    progress = {'phase':'Uploading persistent volumes','updated_at':now.isoformat(),'items':{'data':{'name':'production/postgres-data','status':'running','mode':'snapshot','bytes_uploaded':10485760}}} if status == 'running' else {}
    sql = 'INSERT INTO backup_runs (id, job_id, agent_id, target_id, workflow_id, run_id, status, start_time, end_time, bytes_scanned, bytes_uploaded, dedup_ratio, chunk_count, error_message, pbs_snapshot_id, details, progress) VALUES (' + ','.join([literal(run_id), literal(job['id']), literal(job['agent_id']), literal(target['id']), literal('verification-'+run_id), literal(''), literal(status), literal((now-dt.timedelta(minutes=4)).isoformat()), 'NULL' if status == 'running' else literal(now.isoformat()), '1073741824', '160432128', '6.7', '256', literal('Verification fixture: one PVC could not be backed up' if status == 'failed' else ''), literal('host/archive-node-01/'+now.isoformat()), literal(json.dumps(details or {}))+'::jsonb', literal(json.dumps(progress))+'::jsonb']) + ');'
    subprocess.run(['docker','compose','-f','deploy/compose.ui-test.yml','exec','-T','postgres','psql','-U','ui_test','-d','ui_test','-v','ON_ERROR_STOP=1'],input=sql.encode(),check=True,stdout=subprocess.DEVNULL)
    body, _ = request('/runs/' + run_id)
    assert 'run-panel' in body and ('every 3s' in body) == (status == 'running')
    detail, headers = request('/runs/' + run_id + '?download=json', api=True)
    assert detail['id'] == run_id and 'attachment;' in headers['Content-Disposition']
print('PASS populated filesystem/database/cluster details, polling and JSON download')

for page in ['dashboard','agents','targets','jobs','kubernetes','runs','tokens','apikeys']:
    body, _ = request('/' + page)
    assert 'id="app"' in body and '<script' not in body
Path('/tmp/fallbck-ui-verification.json').write_text(json.dumps({'base':BASE,'runs':run_ids,'jobs':{k:v['id'] for k,v in jobs.items()},'target':target['id']},indent=2))
print('PASS all populated pages. Test-only records remain at http://localhost:18081 for browser inspection.')
