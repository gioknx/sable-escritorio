import { createHmac, randomBytes } from 'node:crypto';
import { SYNAPSE } from './pins.mjs';

// Segredos novos por execução; ficam só no privado (arquivo 0600 / config dentro da distro descartável).
export function generateSecrets() {
  return Object.freeze({
    username: `ensaio-${randomBytes(4).toString('hex')}`,
    password: randomBytes(24).toString('base64url'),
    registrationSharedSecret: randomBytes(32).toString('hex'),
    macaroonSecretKey: randomBytes(32).toString('hex'),
    formSecret: randomBytes(32).toString('hex'),
  });
}
export const secretValues = s => [s.password, s.registrationSharedSecret, s.macaroonSecretKey, s.formSecret];

// JSON é YAML válido: Synapse lê sem dependência YAML aqui. Loopback HTTP, federação desligada.
export function homeserverConfig(secrets, dataDir) {
  return {
    server_name: SYNAPSE.serverName,
    public_baseurl: `${SYNAPSE.homeserver}/`,
    pid_file: `${dataDir}/homeserver.pid`,
    listeners: [{ port: SYNAPSE.port, bind_addresses: ['127.0.0.1'], type: 'http', tls: false, x_forwarded: false,
      resources: [{ names: ['client'], compress: false }] }],
    database: { name: 'sqlite3', args: { database: `${dataDir}/homeserver.db` } },
    media_store_path: `${dataDir}/media_store`,
    signing_key_path: `${dataDir}/signing.key`,
    registration_shared_secret: secrets.registrationSharedSecret,
    macaroon_secret_key: secrets.macaroonSecretKey,
    form_secret: secrets.formSecret,
    enable_registration: false,
    report_stats: false,
    enable_metrics: false,
    federation_domain_whitelist: [],
    trusted_key_servers: [],
    suppress_key_server_warning: true,
    allow_public_rooms_over_federation: false,
    serve_server_wellknown: false,
    url_preview_enabled: false,
    presence: { enabled: false },
  };
}

// Algoritmo documentado do Synapse para /_synapse/admin/v1/register (HMAC-SHA1).
export function registrationMac(sharedSecret, nonce, username, password, admin = false) {
  return createHmac('sha1', sharedSecret)
    .update(nonce).update('\x00').update(username).update('\x00').update(password).update('\x00')
    .update(admin ? 'admin' : 'notadmin').digest('hex');
}

async function json(response, label) {
  const text = await response.text();
  if (!response.ok) throw new Error(`${label}: HTTP ${response.status} ${text.slice(0, 256)}`);
  return JSON.parse(text);
}

// Cria a conta sintética e encerra o token/dispositivo da criação; o único dispositivo passa a ser o do Sable.
export async function registerSyntheticAccount(baseUrl, secrets) {
  const url = `${baseUrl}/_synapse/admin/v1/register`;
  const { nonce } = await json(await fetch(url, { redirect: 'error' }), 'register nonce');
  const body = { nonce, username: secrets.username, password: secrets.password, admin: false,
    mac: registrationMac(secrets.registrationSharedSecret, nonce, secrets.username, secrets.password) };
  const created = await json(await fetch(url, { method: 'POST', redirect: 'error', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body) }), 'register');
  const out = await fetch(`${baseUrl}/_matrix/client/v3/logout`, { method: 'POST', redirect: 'error',
    headers: { authorization: `Bearer ${created.access_token}`, 'content-type': 'application/json' }, body: '{}' });
  if (!out.ok) throw new Error(`registration logout: HTTP ${out.status}`);
  return { userId: created.user_id, registrationDeviceRemoved: created.device_id };
}

// Executado pelo python da distro sobre o SQLite real do Synapse sintético. Somente leitura.
export const SQLITE_CHECK_PY = String.raw`
import json, sqlite3, sys, os
db, room_id, event_id, user_id, canary = sys.argv[1:6]
import shutil, tempfile, time
src = db
# WSL1 não suporta os locks do SQLite sobre o arquivo ao vivo: lê-se uma cópia privada. Nunca se copia o -shm (índice de memória
# compartilhada do arquivo vivo, inconsistente na cópia); o SQLite reconstrói o índice do -wal copiado. Retenta até o evento aparecer.
row = None; types = {}
for attempt in range(20):
    tmp = tempfile.mkdtemp(prefix='synapse-ro-'); db = os.path.join(tmp, 'copy.db')
    for suffix in ('', '-wal', '-journal'):
        if os.path.exists(src + suffix): shutil.copyfile(src + suffix, db + suffix)
    con = sqlite3.connect(db)
    row = con.execute('select e.type, j.json from events e join event_json j using(event_id) where e.event_id=? and e.room_id=?', (event_id, room_id)).fetchone()
    if row: break
    types = dict(con.execute('select type, count(*) from events where room_id=? group by type', (room_id,)).fetchall())
    if attempt < 19: con.close(); time.sleep(1)
out = {'eventFound': row is not None}
if row is None: out['roomEventTypesSeen'] = types
if row:
    ev = json.loads(row[1]); content = ev.get('content', {})
    out.update(eventType=row[0], hasBody='body' in content, contentAlgorithm=content.get('algorithm'), sender=ev.get('sender'))
enc = con.execute("select j.json from current_state_events c join event_json j using(event_id) where c.room_id=? and c.type='m.room.encryption' and c.state_key=''", (room_id,)).fetchone()
out['roomEncryption'] = json.loads(enc[0]).get('content', {}).get('algorithm') if enc else None
out['devices'] = sorted(r[0] for r in con.execute('select device_id from devices where user_id=? and not hidden', (user_id,)))
con.close()
needle = canary.encode('utf-8'); found = False
for name in (db, db + '-wal', db + '-journal'):
    if os.path.exists(name):
        with open(name, 'rb') as f:
            if needle in f.read(): found = True
out['canaryPlaintextInDatabase'] = found
print(json.dumps(out, sort_keys=True))
`;

export function validateDatabaseEvidence(evidence, { userId, deviceId }) {
  const problems = [];
  if (evidence.eventFound !== true) problems.push('event not stored');
  if (evidence.eventType !== 'm.room.encrypted') problems.push('stored type is not m.room.encrypted');
  if (evidence.hasBody !== false) problems.push('encrypted event content has body');
  if (evidence.contentAlgorithm !== 'm.megolm.v1.aes-sha2') problems.push('content algorithm');
  if (evidence.roomEncryption !== 'm.megolm.v1.aes-sha2') problems.push('room m.room.encryption algorithm');
  if (evidence.sender !== userId) problems.push('sender');
  if (evidence.canaryPlaintextInDatabase !== false) problems.push('canary plaintext present in server database');
  if (!Array.isArray(evidence.devices) || evidence.devices.length !== 1 || evidence.devices[0] !== deviceId) problems.push('device set is not exactly the Sable device');
  return { ok: problems.length === 0, problems };
}
