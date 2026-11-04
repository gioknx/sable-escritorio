# Download autenticado → NSIS → reabertura explícita (ensaio descartável)

Integração isolada, dona deste ensaio; não é Sable, instalador de release,
ativação nem auto-update pronto para produção. Linux só produz UNIT: o driver
fora de Windows x64 retorna `78`, `BLOCKED`, `nativeElectron:false`.
A execução Native ainda é hipótese até os recibos reais da workflow manual.

## Fontes congeladas e delta

- W: `../update-auth-windows/update-auth.cjs`, base `a5ea2b6`.
- Core: `../update-auth-policy-sqlite/{policy,store}.cjs`, base
  `f01a3b97eabfc676e6d46cec62839dd3fda10f27`.
- Controle, ambiente allowlist, CA pública e handshakes reaproveitam
  `../update-auth-sqlite/{driver,startup-control}.cjs` e
  `../update-auth-policy-sqlite/{driver,electron-main}.cjs` (somente no pai Node).
- `driver.verifyClone()` compara o delta de W com CRLF/LF normalizados apenas
  nesse comparador; inventários preservam hashes dos bytes reais. Retira a Policy
  de arquivo e seus imports/helpers privados, importando a Policy SQLite aprovada
  e apontando dependências à instalação W. Provider, download FULL `receive`
  Node/TLS, rehash, guard, close, doInstall e spawn permanecem idênticos.
  Não há trust Chromium, bypass TLS, CA do Windows ou dependência nova.

## Execução e contrato

`native-nsis-check.yml` executa syntax, UNIT e regressões congeladas no Ubuntu.
`native-nsis-windows.yml` é **somente workflow_dispatch**, Windows GHA descartável.
A mãe integra a fonte/default branch antes de qualquer dispatch. Não usar Ronald.
A workflow prepara Electron oficial 45.0.0, ZIP SHA256
`ae53887a23bb640369c93dbd38c408a2af5c0deb86f2fa76c6c244cb444b7f47`,
Node 24.22.0 e `npm ci --ignore-scripts` da instalação W existente.
Compilador temporário oficial, autorizado e pinado, sem depender da imagem:
`https://github.com/electron-userland/electron-builder-binaries/releases/download/nsis@1.2.1/nsis-bundle-3.12.tar.gz`,
SHA256 `56997fdefe25e7928a1a68b4583d08b240b66cf660234053b20131a74cc082f4`.
Proveniência fornecida pela mãe: app-builder-lib 26.18.0, tar npm com SRI
verificado; `out/toolsets/windows.js:165–183` + `util/electronGet.js`.
Hash é exigido ANTES de `tar.exe`; prefixo real `nsis-bundle/`, executável real
`windows/Bin/makensis.exe` (não o shim), `NSISDIR=<bundle>/windows` apenas no
ambiente do compilador. Identidade/versão Windows são medidas, não presumidas
`v3.12` (bundle declara 3.12, versão Linux informada pela mãe é CVS).
Archive/tooltree ficam privados e são removidos no fim. Sem npm/global install,
7zip, fallback ou skip. A identidade Windows ainda precisa da medição real.

Com runtime e compiler já preparados **somente no runner**:

```
node experiments/update-auth-native-nsis/driver.cjs --electron <RUNNER_TEMP/runtime/electron/electron.exe> --out <RUNNER_TEMP/public-exclusivo> --compiler <runtime/nsis-toolset/nsis-bundle/windows/Bin/makensis.exe>
```

Primeiro controle app-ready usa EXE pristino, antes de empacotar fixtures.
A/B usam EXE idêntico ao ZIP e `resources/app/package.json` ordinário, sem builder
ou ASAR. `app.isPackaged`, getVersion, adapter `ElectronAppAdapter` genuíno,
config `resources/app-update.yml`, caminhos reais e versões são exigidos Native.
O formato de empacotamento ordinário permanece hipótese até essa medição.
`new AuthenticatedNsisUpdater(options)` omite adapter; initialise → close →
constructor reabre Core SQLite, seq2/v2.2.3 autenticado e idempotente.
Os sources/deps são cópias regulares inventariadas, sem `.bin` (launch links de
npm não utilizados), sem symlink; inventário externo tem hash no config limitado.

O NSIS FULL inclui runtime B inteiro, app B e dependências Core/W. `user`, `/S`,
InstallDir compilado exclusivo sob RUNNER_TEMP, sem registro, UAC, atalhos,
protocolos ou uninstaller. Não aceita diretório arbitrário/admin/FORCERUN.
Antes do positivo, mesmo envelope válido/hash real serve bytes de tamanho igual
com um bit alterado no HTTPS. Só erro específico de hash/tamanho é aceito;
falha de TLS, infraestrutura ou assinatura nunca vira negativo esperado.
Conta download e exige alvo/READY/INSTALLED ausentes.

No positivo, updater genuíno faz guard/download/rehash e
`quitAndInstall(true,false)`. O recibo A `LAUNCH_REQUESTED` é intenção, nunca
instalação concluída. NSIS escreve PID real via kernel32, aguarda ACK com prazo;
o driver observa CIM/caminho/argv/cadeia até PID real A antes de liberar a cópia,
e captura handle OS do instalador para observar saída com prazo e exigir exit0.
`INSTALLED` só vem após escrita de arquivos; o driver verifica inventário/hash de
**todos** os arquivos instalados. Depois ele, explicitamente, executa B instalado,
valida versão Native 2.2.3, PID distinto e canário do mesmo userData A.
B não importa updater nem chama checkForUpdates. `autoRunAppAfterInstall=false`
é preservado. Reabertura é **driver-driven**, não updater-iniciada.
Prazos e observação de JSON/processos substituem esperas fixas de instalação.
Cleanup em finally encerra filhos observados e remove toda árvore privada.

## Evidência pública e limites

Somente allowlist explícita de JSON limitado, hashes/inventários, recibos,
PIDs/caminhos/argv/exits e CA **pública** é carregada. Chaves Ed25519 privadas
ficam na memória; chave TLS privada, runtime, ZIP e instalador ficam fora dos
artifacts e são removidos. Não publicar EXEs, PEM privado ou token. Perfis,
cacheName, home, temp e userData exclusivos; ambiente dos filhos não propaga
GH tokens, NODE_OPTIONS, ELECTRON_RUN_AS_NODE ou TLS0.

PASS Native requer negativo específico + cadeia OS genuína + arquivos instalados
íntegros + B Native 2.2.3/canário + fontes/runtime imutáveis. Process creation
accepted não basta. Não há FakeUpdater, proxy positivo Node ou fallback de prova.
Baseline Core17/W14/S24 e NativePolicyHarness12 continuam sem alterações.

## Verificação local (não Native)

```
for f in update-auth electron-main driver; do node --check experiments/update-auth-native-nsis/$f.cjs; done
node --test experiments/update-auth-native-nsis/native.test.cjs
node experiments/update-auth-policy-sqlite/run-unit.cjs
node experiments/update-auth-windows/run-unit.cjs
node --test experiments/update-auth-sqlite/probe.test.cjs
node --test experiments/update-auth-policy-sqlite/native.test.cjs
actionlint .github/workflows/native-nsis-check.yml .github/workflows/native-nsis-windows.yml
git diff --check
```
