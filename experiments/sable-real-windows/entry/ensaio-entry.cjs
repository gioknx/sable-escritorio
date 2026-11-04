'use strict';
// Entrada SOMENTE do pacote de ensaio descartável (main: dist/ensaio-entry.cjs). Antes do main.cjs real:
// 1) app.setPath('appData', raiz privada) e env de caminhos privados (home/temp/APPDATA/LOCALAPPDATA);
// 2) CA pública efêmera pinada desta execução no conjunto padrão do Node (tls.setDefaultCACertificates);
// 3) CDP loopback por switch; 4) testemunha por PID. Configuração validada em ensaio-launch.cjs.
// Sem configuração válida ou sem a API de CA: recusa (exit 78), nunca cai no perfil real nem relaxa TLS.
const { app } = require('electron');
const { installCa, loadLaunch, writeWitness } = require('./ensaio-launch.cjs');

let launch = null;
try {
  launch = loadLaunch(process.execPath, process.argv);
  Object.assign(process.env, launch.env);
  installCa(launch.ca);
  app.setPath('appData', launch.appData);
  app.commandLine.appendSwitch('remote-debugging-port', String(launch.cdpPort));
  writeWitness(launch, { pid: process.pid, ppid: process.ppid, execPath: process.execPath, codeDir: __dirname });
} catch (error) {
  process.stderr.write(`SABLE_ENSAIO_REFUSED ${String(error && error.message).slice(0, 256)}\n`);
  launch = null;
}

if (!launch) app.exit(78);
else require('./main.cjs');
