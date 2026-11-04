# SQLite capability / reopen probe

Ensaio isolado, anterior ao adapter/Policy: **somente main real do Electron
45.0.0, Windows x64** pode produzir `capability.json` com `status: PASS`.
Não altera o experimento `update-auth-windows`, instaladores ou truststore.

```powershell
node experiments/update-auth-sqlite/driver.cjs --electron "$env:RUNNER_TEMP\benchmark\electron\electron.exe" --root "$env:RUNNER_TEMP\benchmark" --out "$env:RUNNER_TEMP\evidence-sqlite"
```

O binário deve ser obtido/verificado pelo chamador. `--root` deve existir e
ser pasta física estritamente sob `RUNNER_TEMP`; o `.exe` deve estar dentro
dela. Caminhos são absolutos; symlinks/junctions nos componentes são recusados.
`--out` pode ser separado, mas deve ter caminho físico; evidência anterior
não é sobrescrita. Execute em árvore exclusiva do ensaio, sem mutação concorrente
por outros processos (a validação de caminhos não é uma defesa contra TOCTOU).

O driver cria uma subpasta nonce própria e preserva tudo para inspeção: cópia
SHA-256 do probe, banco descartável, perfis/cache/logs/TEMP e receipts `write`
e `read`. APPDATA/LOCALAPPDATA/HOME/USERPROFILE também são isolados. O filho
recebe apenas ambiente Windows mínimo, sem tokens, `NODE_OPTIONS` ou
`ELECTRON_RUN_AS_NODE`. Não cria BrowserWindow, protocolo, atalho ou instalador;
não usa `--no-sandbox`; desabilita aceleração de hardware antes de ready.

Cada processo tem prazo de execução de 20 s, seguido de até 2 s para terminar
após timeout; stdout/stderr são limitados a 64 KiB cada. O primeiro cria apenas
o banco temporário, confere SQLite >=3.51.3 e compile_options, configura e lê
`WAL`, `FULL (2)`, `EXCLUSIVE` e busy timeout de 1000 ms, faz
`BEGIN IMMEDIATE / INSERT / COMMIT` e fecha a conexão. O segundo processo abre
o mesmo banco **read-only**, não cria tabela nem insere canário e confere
integridade/conteúdo/pragmas. PID real, runtime, fase, nonce, banco e hash do
probe devem corresponder aos receipts. `process.versions` é registrado, sem
imprimir o ambiente.

Saídas: `0 = PASS` somente após as duas fases; `78 = BLOCKED` para host/runtime,
módulo ausente ou SQLite antigo; `1 = erro`. No Windows, após validação do
CLI/caminhos, o resumo fica em `--out/capability.json`; falhas anteriores à
validação saem no stderr. Em outro SO o driver só emite JSON `BLOCKED`, sem
executar o binário nem criar evidência nativa.

Diagnóstico de fase que falha (inclusive sem receipt): o JSON inclui
`phases[].diagnostics.stdoutTail` e `stderrTail`, cada um limitado a 4 KiB
em UTF-8, sem cortar caracteres multibyte. São caudas dos buffers já capturados
nos logs do driver, não nova captura: se `stdoutTruncated`/`stderrTruncated`
for verdadeiro, o trecho pertence aos primeiros 64 KiB preservados, não ao fim
da saída total. Nenhum caminho fornecido pelo receipt é usado para ler logs;
não há dump de ambiente nem novo upload. Os trechos são apenas diagnóstico:
não autorizam PASS nem substituem receipts, nonce/PID/hash ou as duas fases.

No run Windows `41787197000`, a fase `write` terminou com exit code
`2147483651`, sem receipt; o relatório permaneceu `ERROR`,
`nativeElectron: false`. A causa continua **desconhecida**: o JSON arquivado
não contém stdout/stderr, e esse resultado não prova ausência de SQLite.
O run posterior `41791507819` também falhou em `write`, sem receipt,
com o mesmo exit code; stdout contém somente `\r\n` e stderr está vazio,
sem truncamento. A causa permanece **desconhecida**; não demonstra ausência
de SQLite. A instrumentação abaixo não foi executada no Windows nesta etapa.

### Diagnóstico adicional de inicialização

Antes de cada spawn, o driver cria `logs/<fase>/` exclusivo e passa somente
`--enable-logging=file` e `--log-file=<runDir>/logs/<fase>/chromium.log`
antes do entrypoint. Segundo a [documentação oficial de switches](https://www.electronjs.org/docs/latest/api/command-line-switches),
logging em arquivo é mais confiável no Windows, requer logging habilitado e
diretório existente. Isso **não garante** captura antes de um crash inicial.
O [default_app do Electron 45.0.0](https://raw.githubusercontent.com/electron/electron/v45.0.0/default_app/main.ts)
localiza o script pulando switches e o carrega com
`await import(url.pathToFileURL(filePath).toString());`, sem modificar
`process.argv` nesse carregamento. CJS importado dinamicamente não satisfaz
`require.main === module`: esse defeito do guard foi reproduzido em UNIT antes
da correção. O entrypoint agora roda no processo `browser` ou como CLI direto;
imports de helpers no Node continuam sem efeitos, e o CLI Node continua
BLOCKED/78. Isso não identifica a causa dos crashes Windows históricos.
O wrapper de argumentos aceita apenas o layout comum ou os dois
switches exatos antes do entrypoint, com log path correspondente à fase;
o parser de argumentos do probe não ignora switches desconhecidos.

Após argumentos validados e cálculo do hash, o main registra um checkpoint
local pequeno em `logs/<fase>/checkpoint.json`. O último marco é um de:
`js-entry`, `electron-loaded`, `paths-configured`, `app-ready`,
`sqlite-loaded`, `exercise-complete`, `receipt-written`. O checkpoint contém
somente schema, marco, fase, PID, nonce e SHA-256 do probe; não inclui ambiente,
canário, dumps ou segredos. A escrita é best-effort e não muda aceitação.
`receipt-written` também pode corresponder a receipt BLOCKED/ERROR;
nenhum marco é receipt, prova nativa, atestado de PASS ou causa do crash.

Na fase que falha, `diagnostics.nativeLog` informa disponibilidade e inclui
somente cauda UTF-8 de até 4 KiB, lida com seek bounded de arquivo regular,
sem seguir symlink/junction. `diagnostics.checkpoint` só inclui campos
whitelisted após conferir PID/nonce/fase/hash e o marco permitido; leitura
limitada a 4 KiB. Caminhos são derivados do estado de lançamento do driver,
nunca de campos do receipt/checkpoint. Ausência, corrupção ou caminho inseguro
produzem `available: false`, preservando o erro original; ausência de checkpoint
não identifica um estágio. Não há alteração de uploads/workflows JSON-only,
flags de sandbox/headless, critérios de PASS ou `nativeElectron`.
Esta alteração só preserva diagnóstico em execuções futuras; não recupera
logs históricos nem constitui nova execução Windows ou evidência nativa.

### Controle independente, sem SQLite

Antes das fases reais, o driver copia e calcula SHA-256 de `startup-control.cjs`
em `startup-<aleatório>/`, com perfil, HOME, APPDATA, cache, TEMP e logs próprios,
separados do probe/banco. Usa o **mesmo `.exe`**, `runChild`, ambiente mínimo,
prazo e os dois switches de logging; não há outro runtime ou fallback.
O controle não importa o probe nem `node:sqlite`, não cria banco ou janela.
Configura userData/sessionData e demais caminhos antes de `whenReady()`, marca
`electron-loaded` e `app-ready`, e encerra por `app.exit`.

Em Electron browser, a entrada independe de `require.main`. Após verificações
locais de segurança do destino e limites de tamanho, a primeira marca
`js-entry` precede parser e guard de runtime. O JSON regular de até 4 KiB em
`<controlDir>/logs/startup/checkpoint.json` contém fase `startup`, PID/runtime
reais, hash próprio, nonce, booleano `requireMain` e apenas argv do lançamento
controlado (até 16 strings, 1024 bytes por string, 2048 bytes no conjunto).
Não inclui ambiente. Sem Electron 45.0.0 Windows x64 real, o controle emite
BLOCKED/78; caminho/argumentos inválidos e falha de escrita não viram sucesso.
Imports Node de helpers são inertes; executar o controle no Node não certifica
Electron nem SQLite.

`capability.json.control` preserva resultado do processo, marca whitelisted
vinculada a nonce/PID/hash/fase e argv esperados: lançamento original ou exatamente
sem os dois switches nativos de logging, como aceita o parser; nenhum outro argumento
é alterado. Preserva caudas UTF-8 de stdout, stderr e log nativo de até 4 KiB cada. A leitura é limitada, de arquivo regular sem
links; nenhum caminho vindo do JSON é seguido. Os arquivos são derivados
somente do estado do driver. Hash da cópia também é conferido antes/depois.
Marca `READY` significa apenas diagnóstico de startup, **nunca PASS**.
Se o controle falhar, o relatório mantém erro explícito, causa desconhecida e
`sqlitePhases: not-started`; as fases SQLite não são executadas e não há
fallback. Se passar, ambas as fases SQLite originais continuam obrigatórias,
com runtime/PIDs distintos/nonce/hash/paths, WAL/FULL e SQLite >=3.51.3 intactos.
Somente elas podem produzir `PASS`/`nativeElectron: true`. Nenhum controle
prova SQLite, durabilidade, causa histórica ou elimina a necessidade de prova
Windows real. O artefato continua sendo o JSON existente, sem ampliar upload.

```sh
node --test experiments/update-auth-sqlite/probe.test.cjs
node --check experiments/update-auth-sqlite/electron-main.cjs
node --check experiments/update-auth-sqlite/driver.cjs
node --check experiments/update-auth-sqlite/probe.test.cjs
node --check experiments/update-auth-sqlite/startup-control.cjs
git diff --check
git diff --exit-code a5ea2b6 -- experiments/update-auth-windows
```

Validação local UNIT (Linux, Node v24.20.0), base
`b39e500a391f4e1b1035d3e94a753ce499769bfa`: o comando real
`node --test experiments/update-auth-sqlite/probe.test.cjs` terminou com
**24 pass, 0 fail, 0 skip** (19 anteriores + 5 novos). Os quatro comandos
`node --check` acima, `git diff --check` e
`git diff --exit-code a5ea2b6 -- experiments/update-auth-windows` terminaram
com código zero. A reprodução anterior à edição usou import dinâmico do CJS
real e conferiu `require.main !== require.cache[file]`; o teste permanente
confere também fixture CJS via import/CLI e o predicado de entrada.
Capture os hashes da **mesma árvore testada**; não reutilize um recibo de outra edição:

```sh
sha256sum experiments/update-auth-sqlite/{driver,electron-main,probe.test,startup-control}.cjs
```

Nenhuma execução Windows foi feita nesta etapa. Testes UNIT usam o SQLite
builtin do Node e não atestam Electron/Windows.
As APIs foram consultadas na documentação oficial [Node v24.22.0 SQLite](https://nodejs.org/docs/v24.22.0/api/sqlite.html)
e [Electron app](https://www.electronjs.org/docs/latest/api/app).
Este probe **não prova autenticação, antirollback, durabilidade sob falha,
recuperação de crash, concorrência, segurança do adapter ou NSIS**. Nem os
receipts nem o hash são assinatura/atestado contra um host adversário.
Backports seguros anteriores a 3.51.3 são deliberadamente recusados.
