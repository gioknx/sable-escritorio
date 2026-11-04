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

```sh
node --test experiments/update-auth-sqlite/probe.test.cjs
node --check experiments/update-auth-sqlite/electron-main.cjs
node --check experiments/update-auth-sqlite/driver.cjs
node --check experiments/update-auth-sqlite/probe.test.cjs
```

Testes UNIT usam o SQLite builtin do Node e não atestam Electron/Windows.
As APIs foram consultadas na documentação oficial [Node v24.22.0 SQLite](https://nodejs.org/docs/v24.22.0/api/sqlite.html)
e [Electron app](https://www.electronjs.org/docs/latest/api/app).
Este probe **não prova autenticação, antirollback, durabilidade sob falha,
recuperação de crash, concorrência, segurança do adapter ou NSIS**. Nem os
receipts nem o hash são assinatura/atestado contra um host adversário.
Backports seguros anteriores a 3.51.3 são deliberadamente recusados.
