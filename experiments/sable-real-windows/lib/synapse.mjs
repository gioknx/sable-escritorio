import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
export const SQLITE_CHECK_PY = readFileSync(new URL('./sqlite-check.py', import.meta.url), 'utf8');

// Public diagnostic: only allowlisted event types/algorithms, booleans and counts. Anything else from the
// database is reported as 'other' / a count, so server-side text can never reach a public report.
const PUBLIC_EVENT_TYPES = new Set(['m.room.create', 'm.room.encrypted', 'm.room.encryption', 'm.room.guest_access',
  'm.room.history_visibility', 'm.room.join_rules', 'm.room.member', 'm.room.message', 'm.room.name', 'm.room.power_levels']);
const publicType = value => value == null ? null : PUBLIC_EVENT_TYPES.has(value) ? value : 'other';
const publicAlgorithm = value => value == null ? null : value === 'm.megolm.v1.aes-sha2' ? value : 'other';
const publicCount = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const publicBool = value => typeof value === 'boolean' ? value : null;
export function databaseDiagnostic(evidence, { userId, deviceId }) {
  const types = {};
  for (const [type, count] of Object.entries(evidence.roomEventTypesSeen ?? {})) {
    const key = publicType(type); types[key] = publicCount(types[key]) + publicCount(count);
  }
  return {
    eventFound: publicBool(evidence.eventFound),
    roomEventTypesSeen: types,
    eventType: publicType(evidence.eventType),
    hasBody: publicBool(evidence.hasBody),
    contentAlgorithm: publicAlgorithm(evidence.contentAlgorithm),
    roomEncryption: publicAlgorithm(evidence.roomEncryption),
    identifiersMatch: publicBool(evidence.identifiersMatch),
    databaseConsistent: publicBool(evidence.databaseConsistent),
    senderMatches: evidence.sender === userId,
    deviceMatches: evidence.devices?.length === 1 && evidence.devices[0] === deviceId,
    canaryPlaintextInDatabase: publicBool(evidence.canaryPlaintextInDatabase),
  };
}

export function validateDatabaseEvidence(evidence, { userId, deviceId }) {
  const problems = [];
  if (evidence.databaseConsistent !== true) problems.push('database consistency not proved');
  if (evidence.identifiersMatch !== true) problems.push('event identifiers do not match');
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
