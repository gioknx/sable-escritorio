// PASS só com TODOS os elos medidos nesta execução e correlacionados. Qualquer ausência => ERROR.
export const REQUIRED = Object.freeze([
  'inputsVerified',          // fonte/receita/DLL/Electron/rootfs/wheel por hash
  'packagesBuilt',           // dois NSIS genuínos, guards office/afterPack, versões 2.2.2 e 2.2.3
  'synapseLoopback',         // Synapse real WSL1 loopback, federação desligada, conta sintética
  'seedInstalled',           // NSIS 2.2.2 instalado, inventário integral
  'seedCoreLogin',           // janela/Core/DLL reais + login RPC + restore após reload
  'encryptedEventConfirmed', // evento remoto confirmado + SQLite com m.room.encrypted sem body
  'negativeTamperRejected',  // instalador adulterado em trânsito não instala nem muda conta
  'updateDownloadedHint',    // download autenticado pelo SDK e hint real gravado
  'closedToTrayNoInstall',   // X esconde; nada instalado
  'abruptStopOwnPids',       // término abrupto só de PIDs próprios observados
  'installerChain',          // seed -> instalador (/D último) -> 2.2.3 pelo instalador
  'installerExitZero',
  'installedInventory',      // inventário integral + versão asar/PE/registro 2.2.3
  'cdpBoundToReopened',      // CDP do processo aberto pelo instalador (pid do browser)
  'sameAccountDevice',       // restore sem login, mesmo account/user/device, needs_reauth false
  'decryptedSameEvent',      // mesmo event_id decifrado com o mesmo texto
  'selfNoUpdate',            // SDK genuíno: versão instalada sem atualização
  'evidenceAudited',         // allowlist + secret scan
]);

export function decide(platform, checks) {
  if (platform !== 'win32') return { status: 'BLOCKED', exitCode: 78, nativeAuthorization: false, missing: [...REQUIRED] };
  const missing = REQUIRED.filter(name => checks[name] !== true);
  const unknown = Object.keys(checks).filter(name => !REQUIRED.includes(name));
  if (missing.length || unknown.length) return { status: 'ERROR', exitCode: 1, nativeAuthorization: false, missing, unknown };
  return { status: 'PASS', exitCode: 0, nativeAuthorization: true, missing: [] };
}
