# Ensaio do Sable real no Windows descartável

Estado: ensaio manual, aprovado uma vez no Windows descartável em 05/11/2026 (ver "Resultado medido" no fim); não é publicação nem ativação.
Dono: mãe da integração; resultado desejado: instalar a nova versão automaticamente,
reabrir pelo instalador e restaurar a mesma conta/dispositivo e mensagem decifrada.
A versão em uso, Ronald e produção não são destinos de teste.

## Escopo da preparação

Somente esta pasta: fontes/driver, preparo Synapse WSL, helpers de empacotamento,
testes Node de partes puras, pins/dependências e esta README.
Não editar CI, AGENTS, patches, perfis ou módulos dos outros operários.
Sem push, publicação ou execução Windows nesta fatia de preparação (a execução consta no fim).
Linux deve produzir BLOCKED exit78 no driver Native, nunca PASS simulado.
Nenhum Stub/TODO, FakeUpdater, pid forjado, override packaged/TLS/sandbox.

Os módulos reais estão em ../desktop-update e ../desktop-bridge.
O segundo está acrescentando preparePendingUpdateBeforeStart(), antes do Core/UI,
com orçamento de início de aproximadamente 3 segundos e latch que proíbe reiniciar
após abrir a interface. Usa hint opcional fora da árvore canônica, sem autoridade,
checagem assinada/SDK/cache/rehash e uma tentativa por versão. Normal quit não
reabre; início pré-UI e reinício manual usam --force-run. O primeiro corrige
retomada WAL autenticada depois de término abrupto, sem reset/cópia fallback.
Não editar essas pastas; a mãe consolidará a receita/patch após seus testes.

## Material comprovado para evitar recompilar Rust

Fonte real somente leitura:
/home/gio/mind/run/sable-ronald-20261102/download-fonte

Provas offline (não execução):
/home/gio/mind/run/sable-ronald-20261102/sable-real-source-proof-20261104/published-native-identity.json
/home/gio/mind/run/sable-ronald-20261102/sable-real-source-proof-20261104/native-source-identity.json

O instalador publicado em publicacao/sable-2.2.1-escritorio.2-x64.exe tem SHA256
f4997c6857966947a60f8207aecbd21a39a497cb2ea2c2eb49ffc515549001a1.
A extração selecionada na pasta de provas contém:
- resources/app.asar.unpacked/dist/sable_node.node: ef3d908e2941786e99f17520839968baa525861b743f7fb40494f84b7e4e362b
- resources/app.asar.unpacked/dist/sable_audiofox.node: 275745eb3bc6fc6aca39ca0a4ccd39cb89afd4c019cf2bc6925977084205ad04
- resources/app.asar: 9637cca0b6c6dde82c3a173169638729bc2919a063486caca6408dc147a25585

Os dois nativos Windows x64 são byte-exact contra DLL de release e pacote medidos.
As 214 fontes app crates/.cargo/Cargo/rust-toolchain atuais são byte-exact contra
arquivo usado no build Windows, /home/gio/mind/run/wt/executor-9c4cac20/sable-mac-build/src.tgz,
SHA256 4b699d5a1e5d68dece7e34584bbe13009dd26230257650e385102acac042f58c.
Isso não comprova worktree SDK externo nem substitui prova de execução.
Reusar os próprios bytes nativos publicados evita recompilar/mudar o SDK.

O caminho oficial package.mjs chama cargo sempre. A alternativa desta fixture
deve ser explícita: mesmas opções do trecho esbuild de build.mjs e builder26.18
config stable, somente NSIS x64, --publish never. Manter guards office-config,
afterPack/fuses/integridade asar. Gerar main/preload/core-host/audiofox-host reais,
identifier moe.sable.client. Rebuild frontend JS/Svelte para migração Nightly,
com WASM/model bytes comprovados, sem Rust. Não copiar target/node_modules inteiro.
Electron45 winx64 deve vir do archive pinado no workflow Native já validado
em /home/gio/worktrees/sable-escritorio/gio-update-auth-windows; verificar hash real,
não inventar novo download. Se usar electronDist, preserve o pin.
A fonte/receita será materializada pela mãe; aceite --source-root/--recipe-root
explícitos e hashes, sem editar snapshot alheio nem contornar guards.
Versões sintéticas: seed2.2.2 e target2.2.3, acima do floor2.2.1.

## Serviço e conta reais, só loopback

A documentação oficial Windows2025 imagem20261030.317.1 lista WSL1 Enabled.
Não se afirma execução. Preparar import --version1 de distro oficial com SHA
verificado, sem reboot/serviço externo. Synapse real Python/venv na WSL, versão
fixada preferindo o mesmo da bancada/sable existente. HTTP loopback8008,
server_name escritorio.localhost, federação desativada. Resolver apenas
escritorio.localhost no hosts do runner descartável. Sem DNS ou domínio de produção.
A conta usa segredo aleatório por execução, armazenado só no privado, sem valores
em código/artefatos/chat. Não reaproveitar valores da bancada existente.
O login Core RPC aponta para http://escritorio.localhost:8008. Isso é serviço de
teste local, não relaxamento de TLS; o updater continua HTTPS/CA/Ed25519 reais.
Config office source/dist continua play.fablemedia.tech e passa guard original.
Esse login interno não é prova de primeira entrada/SSO; declarar essa distinção.

## Protocolo conhecido e reutilização

Consultar fonte real e bancada/sable/{smoke.mjs,probe.mjs,probe-roundtrip.mjs,lifecycle.test.mjs}.
Não executar smoke web/IndexedDB como se fosse Electron.
O global é window.sableElectron para ações desktop. Core usa MessageChannel:
window.postMessage('sable-core-connect', location.origin, [port2]); no port1,
{id, call:{method,params}}; respostas {id,ok}/{id,err}, eventos em {events}.
auth.login recebe homeserver, identifier de usuário, segredo gerado e reauth_account_id:null.
session.restore{} retorna account_id/user_id/device_id/homeserver/needs_reauth.
session.sync_status é offline/syncing/live/error, não ready.
Após login por port, recarregar UI para restauração normal, sem hook fake.
rooms.create: sala privada text, encrypted=true, federate=false e demais opcionais
nulos/arrays vazios conforme tipos reais. messages.send: texto canário único.
timeline.subscribe: focus live, hidden_events=false; exigir evento remoto confirmado,
não eco local. Após atualização: restore sem login e focus event/event_id, mesmo
texto decifrado. No SQLite do Synapse sintético, confirmar m.room.encrypted,
sem content.body e m.room.encryption=m.megolm.v1.aes-sha2.
Não ler mensagens ou perfis reais. Somente dados sintéticos criados pelo ensaio.

## Isolamento e sequência forte

Runner NTFS/temp exclusivo curto, path-length preflight. Env allowlist sem tokens
CI/NODE_OPTIONS/ELECTRON_FORCE_IS_PACKAGED/ELECTRON_RUN_AS_NODE. Wrapper de teste
somente app.setPath('appData', roaming privado) ANTES carregar main.cjs real;
isso isola sessão appData/identifier/session.json, siblings identifier-account-aN
store/cache e Electron identifier.electron. --user-data-dir sozinho não basta.
Manter app identifier e ElectronAppAdapter padrão genuínos. Nenhum kill/logout Core
na aplicação; forceStop da fixture só PIDs observados que ela mesma criou.
CDP loopback por flag somente no ensaio, sem --no-sandbox.

1. Seed real2.2.2, janela/Core/DLL, login real e sala/evento criptografado confirmados.
2. Atualização assinada2.2.3 baixa pelo SDK e grava hint real; X esconde sem instalar.
3. Terminar abruptamente só processos próprios, simulando ausência de before-quit.
4. Relançar seed: preparo pré-Core/UI deve instalar cache autenticado e NSIS concluir0.
5. A versão2.2.3 abre PELO INSTALADOR --force-run, não pelo driver.
6. Conferir inventário integral instalado, versão pacote/PE e UI (VITE sozinho não
   prova versão interna), processo/parent chain/pids/imagens reais e SDK self-no-update.
7. Restaurar mesma conta/device sem needs_reauth e decifrar mesmo evento sem novo login.
8. Negativo de instalador alterado antes spawn não instala/não reseta conta; retry
   íntegro recupera. Não prometer power-loss/durabilidade/rollback não medidos.

NSIS real usa /S --updated --force-run e /D do diretório físico do executável como
ÚLTIMO argumento; bridge adiciona só esses parâmetros e conserva guard/rehash/spawn
base, sem elevação/shellfallback. Template NSIS contém fallback de processos por
nome/usuário: preflight rejeita qualquer Sable fora do escopo, toda máquina é efêmera.

## Resultado e artefatos

PASS requer TODOS: Native runtime/source hashes/GUI/Core real/instalador/versão
instalada/inventário/reabertura pelo instalador/conta/device/decryption correlacionados.
Spawn sozinho ou reabertura pelo driver não basta. Falha => ERROR com diagnóstico
limitado não autorizante. Node tests são somente UNIT, sem Native claim.
Allowlist de evidência pública: resultado/digests/metadata e PNG de conta sintética;
nenhum perfil, raw account eventlog, token, CA privada ou signer privado.
Secret scan real antes de upload e cleanup próprio finally. Não imprimir segredos.

Nesta preparação: implementar código/Node helpers+testes reais possíveis e BLOCKED78
fora Windows. Testar parser PS se disponível; não usar lacuna como PASS.
Entrega deve nomear entradas que dependem de consolidação da mãe/ensaio Native,
sem declarar Windows pronto. Recibos em:
/home/gio/mind/run/sable-ronald-20261102/sable-real-windows-prepare-20261104/

## Implementação desta pasta (preparação; Native não executado)

Verificação local (Node >= 24, Linux; UNIT apenas, sem claim Native):

    cd sable/desktop-windows-test && node --test test/*.test.mjs
    node driver.mjs; echo $?    # BLOCKED, nativeAuthorization:false, exit 78

O teste de feed usa o runtime real de ../desktop-update (rodar antes
`npm ci --ignore-scripts` lá) e prova que openState/Policy.latest aceitam o envelope
Ed25519 do feed HTTPS com CA própria via NODE_EXTRA_CA_CERTS. Os testes leem as provas
acima (SABLE_PROOF_ROOT/SABLE_SOURCE_ROOT sobrescrevem); ausência falha, não pula.
Não há pwsh neste host: os scripts PowerShell de lib/windows.mjs não foram
parseados nem executados; primeira medida deles é a execução Native.

Execução Native futura (Windows x64 descartável, admin, WSL1 habilitado, pwsh, openssl,
Node 24.22.0), todos os argumentos obrigatórios e absolutos:

    node driver.mjs --source-root <fonte consolidada com pnpm install --frozen-lockfile --ignore-scripts>
      --recipe-root <dir com recipe.json da mãe> --electron-zip <electron-v45.0.0-win32-x64.zip>
      --wsl-rootfs <ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz> --synapse-wheel <matrix_synapse-1.162.0 wheel>
      --out <dir público inexistente>

Entradas que dependem da mãe: fonte com patch0015 consolidado (bridge com
preparePendingUpdateBeforeStart e runtime com correção WAL) e `recipe.json`
`{schema:1, patch:{name,sha256}, nativeModules:{sable_node,sable_audiofox:{path,sha256}},
frontendInputs:[{path,sha256}], sourceFiles:[{path,sha256}]}`. O driver recusa pin
divergente (lib/pins.mjs: fontes de build/guards, ferramentas, Electron, rootfs,
wheel, DLLs publicadas). Se a consolidação mudar build.mjs/electron-builder*.yml,
atualizar SOURCE_PINS conscientemente; não há fallback.

Layout 0015 exigido (gerado por ../gerar-patch-desktop-update.mjs da mãe, ainda não
gerado como pronto): electron/src/updater.ts, electron/src/update-runtime-modules.d.ts,
electron/desktop-update/runtime/{policy,store,update-auth,bootstrap}.cjs e main.ts com
`await preparePendingUpdateBeforeStart()`. Todos devem existir e constar de
recipe.sourceFiles. O pin de electron/electron-builder.yml é o pós-0015
(builderSource do gerador sobre o original 41b966f3…; o teste recomputa). O recurso
de updates é criado pela fixture em electron/mindtech-updates.json (lido pelo
extraResources do 0015, removido no finally); a fixture não acrescenta extraResources.
O snapshot pré-0015 é recusado com a lista exata do que falta (teste io).

Módulos: lib/build (vite build + esbuild com as opções de build.mjs, DLL publicada
copiada e conferida, electron-builder `--win nsis --x64 --publish never` com
`extends` da config stable original, afterPack/fuses originais, inspeção de asar,
fuses, recurso de updates e inventário), lib/feed (HTTPS 127.0.0.1, envelope do
runtime, `mindtech-updates.json` no schema do bridge), lib/synapse + lib/wsl,
lib/cdp (CDP loopback + MessagePort próprio ao Core), lib/nsis (CommandLineToArgvW,
comando do instalador e cadeia de processos), lib/windows (PowerShell só por env),
lib/evidence (allowlist + secret scan), lib/verdict (18 elos obrigatórios).

Wrapper (só no pacote do ensaio, `main: dist/ensaio-entry.cjs`; produção intocada):
entry/ensaio-launch.cjs (puro, testado em Node) valida `<raiz>\ensaio-launch.json`
(irmão de `<raiz>\i`): chaves exatas, root = pai físico do diretório do exe, caminhos
absolutos canônicos sem link/junção dentro da raiz, arquivos com nlink 1, marcador
= nonce, portas distintas, CA PEM só certificado, sha256 pinado, X509 CA válida.
O entry então: restaura só USERPROFILE/HOME/APPDATA/LOCALAPPDATA/TEMP/TMP privados;
acrescenta a CA pública efêmera com tls.setDefaultCACertificates([...getCACertificates
('default'), pem]) com dedupe (seed já com NODE_EXTRA_CA_CERTS); app.setPath('appData');
switch remote-debugging-port (porta updated só com `--updated` genuíno do StartApp;
o driver nunca passa --updated); grava testemunha `<appData>\ensaio-witness\<pid>.json`
(nonce, pid/ppid, execPath, modo, porta, sha256 de entry/launch/main.cjs). Sem API de
CA ou configuração válida: exit 78, sem relaxar verificação. NODE_EXTRA_CA_CERTS
tardio não funciona e não é usado. API: Node >= 24.5 (tipos instalados de Electron
45 trazem @types/node 24.19.2 com a função; o Node do Electron 45 não foi executado).
Teste real Node 24.20: só a CA pinada passa (fetch e https), outra CA e hostname
errado continuam rejeitados.

Cadeia do instalador (lib/nsis.mjs; o template real usa ExecShellAsUser sempre):
`launchMode` = `direct` (pai real = PID do instalador) ou `nsis-shell-broker` (pai =
`%SystemRoot%\explorer.exe` com Authenticode Valid CN=Microsoft Windows/O=Microsoft
Corporation, mesmo SID/sessão, criado antes do app). Broker é correlação via shell,
não cadeia direta. Em ambos: único main com args exatamente `['--updated']`, imagem
exata `<raiz>\i\Sable.exe` com sha256 do 2.2.3, PID fora dos spawns do driver, criação
entre início do NSIS e exit + 10 s, driver sem lançar app após o NSIS, instalador filho
do seed com comando exato, SHA512 do payload e exit 0 observados; SID/sessão iguais em
seed/instalador/app; CDP da porta updated no PID e testemunha conferida. Fatos do pai só
lidos pelo observador pwsh; brokers nunca são parados. Qualquer falta: ERROR.

WSL1 sem reboot: `wsl --import <nome> <dir> <rootfs> --version 1`, conferido em
`wsl --list --verbose`; apt python3-venv, venv /opt/sable-ensaio/venv, pip só do
wheel pinado (`--only-binary`), config por stdin (umask 077), `--generate-keys`.
Synapse HTTP só 127.0.0.1:8008, server_name escritorio.localhost (hosts com nonce,
removido no finally), registro aberto desligado, federação/key server 404 exigidos.
Conta: usuário/senha/segredos aleatórios por execução, só na raiz privada; registro
via admin shared-secret e logout do device de criação; o SQLite deve ter exatamente
o device do Sable. Login via RPC auth.login: preservação de conta, não prova SSO.

Updater: CA RSA própria da execução, separada do Synapse HTTP. Chave da CA apagada
após emitir o certificado 127.0.0.1. CA importada em LocalMachine\Root (download do
electron-updater usa Electron net/Chromium) e removida por thumbprint no finally;
Node fetch do runtime: NODE_EXTRA_CA_CERTS no seed e a CA do wrapper em qualquer
reabertura. Signer Ed25519 só em memória. Matrix usa HTTP loopback e não usa CA.

Resultado: `--out/result.json` com os 18 elos; ERROR se qualquer um faltar.
`diagnostics.json` é sempre não autorizante. Público: só a allowlist de
lib/evidence.mjs, cada escrita e a auditoria final passam pelo secret scan.

Elos medidos no Native em 05/11/2026 (run 41992935052): build NSIS real e fuses, scripts pwsh, WSL1/Synapse,
Core/GUI/CDP, download e hint, X para bandeja (visibilityState hidden), cadeia seed->instalador->reabertura
(launchMode nsis-shell-broker), inventário/PE/registro, conta/device/decryption e o negativo de instalador
adulterado (1 download adulterado rejeitado, hint ausente). Ubuntu 24.04 sob WSL1 funcionou.
Limite que continua: as dependências Python do wheel vêm do PyPI sem hash pinado (só binários);
o pip freeze vai para synapse.json.

## Resultado medido e próximo passo (05/11/2026)

Estado: o fluxo completo passou uma vez no Windows descartável do GitHub (run 41992935052, commit 5dd14af
da branch gio/sable-real-windows-4): PASS, nativeAuthorization true, 18 de 18 elos, sem erro de limpeza.
Vale para esta versão do ensaio e para a fonte comprovada acima. Não é publicação nem ativação da
atualização para usuários, não é prova de SSO nem de primeira entrada, e não altera o Sable em uso.
Rodada única: a repetição na mesma versão ainda não foi medida.

Falhas encontradas e causa (as três eram do roteiro, nenhuma do Sable):
- A consulta ao banco do Synapse passava os identificadores pela linha de comando do wsl.exe; o identificador
  do evento começa com $ e o shell da distro o alterava. Agora os parâmetros vão como JSON na entrada padrão
  para um programa Python privado (lib/sqlite-check.py), conferidos por resumo SHA-256, com instantâneo
  consistente (processo do Synapse parado só durante a cópia do banco e do WAL, nunca do -shm). Erro de
  instantâneo, de SQL ou banco incoerente sai com erro e nunca vira "evento ausente".
- A limpeza tratava como erro o processo que já tinha terminado. Agora processo ausente ou que sumiu durante a
  parada é normal; acesso negado ou processo ainda vivo continua erro.
- Aplicar close-to-tray sem useCustomTitleBar fazia o Sable (padrão Windows: barra própria) recriar a janela e
  derrubar a página CDP do roteiro. O roteiro agora mantém a barra própria.

Checagem curta: workflow sable-real-windows.yml com mode=query roda só Synapse real, evento cifrado conhecido
(libolm 3.2.15, hash pinado) e a consulta, sem Sable, compilação ou instalação, e termina QUERY_CHECKED, nunca
aprovação da atualização. Prova (run 41990595436): o caminho antigo reproduz a perda do identificador; o novo
preserva; evento presente passa; ausente, identificador alterado, texto claro e banco incoerente reprovam. As
condições de limpeza "processo já saiu" e "acesso negado/ainda vivo" usam substitutos do Stop-Process; a
ausência real de PID foi medida. O modo full continua sendo o padrão e o único que autoriza.

Tempos medidos (horários dos passos): completo aprovado 4m50s no total, 3m55s no driver: compilação 2m06s,
Synapse 52s, instalação do seed 16s, atualização e validação cerca de 24s. Checagem curta 3m26s, dominada pelo
Synapse sob WSL1 (147s). As rodadas anteriores falhavam depois de 5 a 7 minutos; o ganho vem de isolar a falha e
corrigir na branch, não de acelerar o fluxo. Sem cache nesta entrega.

Fonte de manutenção e cópia de execução: sable/desktop-windows-test (fonte) e experiments/sable-real-windows
(cópia no repo sable-escritorio) são idênticas, incluindo ci/. Única exceção de execução:
test/sealed-input-ci.test.mjs lê .github/workflows e só roda na cópia do repo.

Próximo passo (decisão de produto, fora deste ensaio): integrar o ensaio à main do sable-escritorio e, em
separado, decidir quando a atualização automática passa a valer para usuários.
