# Policy + SQLite: core isolado e prova Native verificada

Esta fatia **não integra** `AuthenticatedNsisUpdater`, app, NSIS ou produção.
O core aprovado permanece inalterado. Policy + store passaram no Electron/Windows
Native no run 41813271165, com recibos conferidos após a execução. Esse PASS é
somente deste núcleo: não autoriza ativação, instalação ou produção.
PASS de UNIT/Node e o canário SQLite anterior não substituem essa prova.

## API nova e dependências existentes

`policy.cjs` exporta `{ Policy }`, diferente da Policy privada em
`../update-auth-windows/update-auth.cjs`. Os helpers de validação, `decode`,
metadados congelados/WeakMap, `guard` e `rehash` preservam as regras desse núcleo.
Não há clock, expiração ou freshness novos, nem API preexistente `verifyEnvelope`.
Nenhum updater, download de instalador ou lançamento de instalador é integrado.
O novo coletor lança somente o runtime Electron pinado para medir este núcleo.

Pré-requisitos: Node 24 com `node:sqlite` builtin e SQLite **>= 3.51.3**;
instalação já existente de SemVer **7.7.3**, fixada por
`../update-auth-windows/package.json` e seu `package-lock.json`. Os módulos usam
explicitamente `../update-auth-windows/node_modules/semver`, sem fallback para
SemVer global, implementação própria ou dependência nova. A Policy confere a
versão instalada. O runner UNIT desta fatia requer Linux, OpenSSL e `prlimit`
já disponíveis; ausência é FAIL, nunca skip. Não instala pacotes.

```js
const { Policy } = require('./policy.cjs');
const options = {
  directory: '/caminho/fisico/pai-existente/ensaio-dedicado-ainda-ausente',
  nonce: 'a'.repeat(64), // fornecedor do ensaio: 64 caracteres hex minúsculos
  publicKey: trustedEd25519PublicKeyPEM,
  feedURL: 'https://origem-confiavel/manifest',
  channel: 'stable',
};
const app = { version: '2.2.1' };
const policy = await Policy.initialise(options, app);
try {
  const info = await policy.latest();
  policy.guard(info); // manifesto autenticado e congelado
  // policy.rehash(caminhoDoArquivoLocal, info); // não baixa nem executa
} finally { policy.close(); }
const reopened = new Policy(options, app); // somente existente, nenhuma rede
reopened.close();
```

`initialise` é explícita e assíncrona: busca HTTPS real, valida envelope Ed25519,
identidade/canal/origin/schema e `version > app.version` **antes** de criar a
árvore. O pai deve existir e ser físico. `mkdir` não recursivo exclusivo e
abertura `wx` reservam diretório e DB. Schema + nonce + primeiro envelope válido
são commitados juntos. A primeira busca não retorna um `info`; somente
`latest()` publica metadados, após COMMIT.

`new Policy(options, app)` só reabre um DB existente, não vazio, integral e com
schema exato, e revalida a assinatura/chave/canal/origin do highwater. **Não**
compara sua versão à instalada durante reopen; `latest()` e `guard()` mantêm
`version > currentVersion`. A versão instalada continua na propriedade pública
`currentVersion`, como no núcleo original. `decode()` verifica um envelope, mas
não autentica um objeto `info` nem autoriza por si só um instalador.

`close()` é idempotente. `guard`, `latest` e `rehash` falham após close ou
poisoning. `decode()` continua sendo verificação criptográfica independente,
como no núcleo original. `guard()` rejeita objetos forjados, mesmo estruturalmente
iguais, e metadados obsoletos após avanço do highwater; todos os níveis do `info`
são congelados. `rehash()` preserva SHA512, tipo/tamanho e verificações de mudança
do arquivo. Não substitui Authenticode nem uma fronteira segura de execução.

## Contrato do store

`store.cjs` exporta `{ Store }` para este núcleo e seus testes, não uma API de
updater. Uma conexão RW por Policy, `allowExtension:false`, WAL, synchronous FULL,
locking EXCLUSIVE e busy timeout 1000 ms; versão e todos os pragmas têm readback.
Uma transação real adquire o bloqueio antes de a instância ser utilizável, e o
modo exclusivo mantém a posse até fechar a conexão.

As únicas estruturas persistentes permitidas são duas tabelas STRICT, singleton:
`meta(id=1,schemaVersion=1,nonce)` e `highwater(id=1,payload,signature)`.
O store exige o SQL completo esperado, propriedades STRICT, cardinalidade,
nonce esperado, ausência de qualquer objeto extra e `integrity_check` com único
resultado `ok`. Seq/version são derivados do payload verificado, nunca de
colunas redundantes. Assinatura e schema são revalidados em read/transaction.

`latest()` verifica a resposta antes do aceite. Dentro de `BEGIN IMMEDIATE`,
relê e verifica highwater, verifica novamente o candidato e aplica as regras:
seq menor rejeitada; seq igual exige payload **e assinatura** idênticos; seq
maior exige versão estritamente maior. Só depois grava e faz COMMIT. Somente
então atualiza highwater em memória e cria/registra o `info` congelado. Chamadas
concorrentes no mesmo processo não podem usar um highwater anterior ao COMMIT
de outra chamada. Erro de candidato antes de escrever faz rollback e preserva
usabilidade; erro SQLite/read/commit/IO bloqueia a instância. Falha de rollback
ou close na limpeza não mascara a falha primária. Close explícito pode reportar
seu próprio erro, mas a instância fica fechada.

Não há `CREATE IF NOT EXISTS`, estado zero presumido, reset, migração, backup,
recuperação automática ou recriação de DB ausente. Inicialização que não commitou
deixa sua árvore para inspeção; não é refeita por init nem aceita como store
vazio. Fixtures inválidas são rejeitadas sem conserto. Não se apagam WAL/SHM no
caminho operacional. Sidecar ausente após close normal **não é corrupção**.

## UNIT reproduzível

Da raiz do repositório:

```sh
for f in policy store test run-unit electron-main driver native.test; do
  node --check experiments/update-auth-policy-sqlite/$f.cjs || exit 1
done
node --test --test-reporter=tap experiments/update-auth-policy-sqlite/native.test.cjs
node experiments/update-auth-policy-sqlite/run-unit.cjs
node experiments/update-auth-windows/run-unit.cjs
node --test experiments/update-auth-sqlite/probe.test.cjs
actionlint .github/workflows/policy-sqlite-check.yml .github/workflows/policy-sqlite-windows.yml
git diff --check
git diff --exit-code f01a3b97eabfc676e6d46cec62839dd3fda10f27 -- experiments/update-auth-policy-sqlite/{policy,store,test,run-unit}.cjs
git diff --exit-code a5ea2b6 -- experiments/update-auth-windows
```

O runner gera certificado/chave efêmeros em diretório temporário privado,
executa teste novo em processo Node com `NODE_EXTRA_CA_CERTS` e remove os PEMs
no final. Não registra chave privada. Não usa `rejectUnauthorized:false`,
`NODE_TLS_REJECT_UNAUTHORIZED=0`, FS monkeypatch, mock SQLite, supressão de fsync
ou proxy de Node. A origem HTTPS loopback permanece viva e idêntica em todos os
filhos. Um filho sem a CA comprova rejeição TLS real. Respostas têm limite 16 KiB,
sem redirect, e preservam limites/schema originais do payload.

A matriz contém no mínimo 17 testes, sem skip/cancel/todo: seq1→seq2/v2.2.3 e
idempotência, rollback/conflicto/versão igual ou menor, assinatura/payload,
validações originais, freeze/WeakMap/guard/rehash/close, respostas concorrentes
fora de ordem, init/reopen, nova assinatura verificada em outro processo,
key/channel/origin/nonce errados, DB ausente/zero/truncado/header determinístico,
schema/objetos extras/cardinalidade/highwater inválido e links reais. As fixtures
conferem sua condição antes da tentativa de reopen e não chamam bytes arbitrários
de prova universal de corrupção.

O teste de lock usa handshake READY de A, conexão própria de B e erro SQLite
real `SQLITE_BUSY`, bounded pelo timeout, depois fecha A e B aceita seq2 de novo.
Não usa espera fixa como atestado. O teste de I/O usa `prlimit --fsize=32768:32768`
em **um filho** e trata SIGXFSZ para observar erro SQLite real no COMMIT de WAL.
Confere a linha do stack, ausência de novo retorno autenticado e poisoning de
`guard/latest`. Não simula power loss nem testa recuperação de crash. Não há
fallback desse teste em outra plataforma. O runner exige TAP atual, pelo menos
17 testes, pass=tests, zero fail/skip/cancel/todo, plano compatível, exit zero e
nenhum sinal; TAP antigo dos 14 testes da baseline não passa. Calcula hashes das
fontes executadas e registra runtime e transcrição nova, não consome recibos
antigos. Hashes/versões/resultados medidos ficam no recibo da execução, não em
valores manuais congelados neste README.

## Evidência Native verificada e procedimento

[Run Windows 41813271165](https://github.com/gioknx/sable-escritorio/actions/runs/41813271165),
head `9e284fbb6333d65eb752240770e233f8329e1cd3`: job **PASS em 43 s**.
Windows x64 em **NTFS**, Electron **45.0.0**, SQLite **3.53.4**; dois controles
independentes, 14 fases, 24 verificações e 16 PIDs distintos. Init/advance,
reopen, monotonicidade, assinatura/payload, TLS real sem CA e oito fixtures
negativas passaram. O holder adquiriu exclusão, outro processo recebeu
SQLITE_BUSY/code5 em **1055,5743 ms**, e após liberar/fechar houve reopen válido.

A conferência posterior baixou somente o artifact público
`policy-sqlite-native-public-41813271165-1`: recibos e processos correspondentes,
56 arquivos copiados com hashes reais, fontes rastreadas iguais ao head do Git
(com normalização CRLF/LF explícita somente na comparação entre plataformas),
pin ZIP/exe, NTFS e ausência de marcador de PEM privado confirmados.
Não houve reparo/reset, instalador, app, NSIS, ativação ou acesso a conta.

A primeira revisão identificou uma guarda S omitida nos workflows. A correção
acrescentou as quatro comparações congeladas antes/depois e rejeitou um mutante
real em scratch; a execução Windows usou a fonte já corrigida.
A fonte foi integrada por merge normal no PR #8; o PR #7 foi fechado por reter
um head desatualizado, sem ignorar a recusa de SHA ou proteção.

`driver.cjs` é um orquestrador Node **assíncrono**, não um proxy que permita
Node certificar Electron. Sua CLI aceita somente `--electron` e `--out`.
Fora de Windows x64 retorna `BLOCKED`, exit 78 e `nativeElectron:false`, sem
criar output ou lançar Electron. Imports Node do main e do driver são inertes.

Uma coleta autorizada requer `RUNNER_TEMP` físico, OpenSSL e PowerShell
`pwsh` disponíveis, runtime oficial em `<RUNNER_TEMP>/runtime/electron/electron.exe`
e seu ZIP em `<RUNNER_TEMP>/runtime/electron.zip`. O output deve ser um diretório
**ainda ausente**, estritamente dentro de RUNNER_TEMP, fora do checkout e separado
do runtime. Exemplo de comando (adapte os caminhos ao ensaio):

```sh
node experiments/update-auth-policy-sqlite/driver.cjs --electron <RUNNER_TEMP>/runtime/electron/electron.exe --out <RUNNER_TEMP>/policy-public-novo
```

O SHA256 do ZIP oficial Electron 45.0.0 win32/x64 é pinado no driver/workflow;
não se confia apenas na string de versão. O driver também lê a entrada única
`electron.exe` do ZIP com a API ZIP nativa do PowerShell e exige igualdade do hash
com o executável fornecido. URL e pins de actions são os mesmos já usados pelo
experimento SQLite de capacidade. Nenhum Electron é baixado pelo driver.

O driver copia `policy.cjs`, `store.cjs`, `electron-main.cjs`, o controle startup
existente e **todos** os arquivos do SemVer 7.7.3 em árvore física sem links.
O layout preserva `../update-auth-windows/node_modules/semver`. Inventário completo
com tamanhos/hashes mede os bytes reais copiados, inclusive LF/CRLF, sem hash
obsoleto manual. Originais e cópias são conferidos antes/depois. Cada processo
Native confere o inventário, caminhos efetivamente carregados, exe/hash, nonce,
argv e runtime real `process.type=browser`, Electron 45.0.0 win32/x64. Só após
`app.whenReady()` faz preflight SQLite em memória (>=3.51.3) e executa a Policy
real. Esse SELECT de versão **não** representa readbacks da conexão privada:
o recibo atribui corretamente WAL/FULL/EXCLUSIVE/busy1000 às asserções do Store
aprovado e hasheado, sem inventar valores exportados.

Antes de qualquer fase SQLite há dois controles independentes do
`../update-auth-sqlite/startup-control.cjs`, com o mesmo exe, allowlist e logging
(com CA e sem CA). Exigem READY/app-ready, hash/nonce/argv/PID correspondente e
exit normal. O parser aceita apenas argv ordinário ou o prefixo exato
`--enable-logging=file` e `--log-file=<log derivado>`; nenhum switch desconhecido
ou `--no-sandbox`. Flags consumidas pelo default_app têm apenas essa variante
explicitamente permitida. NODE_OPTIONS, ELECTRON_RUN_AS_NODE, tokens e bypass TLS
não são herdados. A única adição ao env allowlisted é a CA pública própria,
exceto no teste TLS negativo.

A matriz exige exatamente estas fases, sem skips e com PIDs distintos:

- `init`: HTTPS Ed25519 seq1/v2.2.2, close, leitura do envelope persistido no
  Electron e `Policy.decode` real, reopen, latest seq2/v2.2.3 e idempotência;
  freeze/WeakMap/guard forjado conferidos pela Policy.
- `reopen`: outro processo, seq2, e seis incoming negativos: seq1, seq2
  conflitante, seq3 com versão menor e igual, assinatura ruim e payload alterado.
  Após cada rejeição sem retorno de info, um latest válido confirma seq2.
- `tls-no-ca`: constructor válido, preflight já concluído, fetch rejeitado por
  código específico de certificado real; falha genérica não conta como esperado.
- `holder`, `busy`, `after-lock`: constructor mantém conexão exclusiva, READY
  atômico via fs.watch com deadline, PID comparado ao spawn e depois ao exit real;
  outro processo deve receber SQLITE_BUSY/code5 dentro do limite; ACK libera e
  fecha o holder; um terceiro processo reabre e aceita seq2. Não há sleep fixo.
- Oito fixtures negativas: missing, zero, truncated64, header determinístico,
  extraSchema, badStoredSig, nonce errado e directory junction real. São clones
  **após close Native comprovado**; o Node parent prepara/muta somente negativos,
  verifica precondições e registra `fixtureCreator.runtime=Node` e
  `positiveEvidence=false`. Cada constructor Native deve rejeitar pelo motivo/código
  específico e sem reset do DB. Preparar fixture não conta como Policy Native.

`native.test.cjs` testa parsers, imports inertes, env, cópias/semver, arquivos
reais, watchers/deadlines, fixtures e validadores de recibos/matriz. Seus PIDs e
recibos sintéticos são explicitamente **UNIT, não Native**. Em Linux, symlink de
diretório não é certificado de junction NTFS. Não há SQLite mock, monkeypatch de
FS, execução Windows, fallback ou recibo Native fabricado nesta suíte.

### Evidência pública e workflows

`<out>/result.json` só pode declarar Native PASS após todos os casos exatos,
preflights, códigos, exit/signal/deadlines, fontes, paths, nonces e PIDs conferidos.
Recibos/config/checkpoints são arquivos regulares bounded (64 KiB); summary até
512 KiB; stdout/stderr e logs Chromium preservados até 64 KiB por arquivo após
close, inclusive em erro. Registros antigos nunca são reutilizados/sobrescritos.
A árvore contém inventário, original HEAD, perfis isolados e diagnósticos por fase.

**Classificação PUBLIC:** chaves Ed25519 públicas, certificados públicos,
envelopes assinados/fixtures, fontes/semver, hashes, caminhos efêmeros, PIDs e
logs bounded. A chave Ed25519 privada só existe na memória do parent; a chave
TLS privada fica em diretório temporário separado, **fora de out**, removido no
finally. Nenhuma configuração Native recebe PEM privado. Nenhum token é passado
ou registrado; o upload inclui somente a árvore pública derivada do ensaio.

`.github/workflows/policy-sqlite-check.yml`: Ubuntu manual/push/PR por paths,
Node 24, `npm ci --ignore-scripts` só das dependências já lockadas, sete syntax
checks, UNIT do core/baselines/coletor, actionlint se disponível, hashes e
comparações do core aprovado/Gate0 antes e depois; logs públicos separados.
`.github/workflows/policy-sqlite-windows.yml`: **somente manual**, mede NTFS,
baixa o ZIP oficial pinado, instala as deps lockadas sem scripts, roda o driver,
falha em BLOCKED/ERROR/Nativefalse e faz upload-always somente de out público.
Permissões contents:read; sem credenciais de produção, publicação ou instalação.
O workflow Windows foi despachado e seus recibos reais conferidos no run acima.
A coleta comprovou Policy + store, não instalação nem atualização completa.

## Ameaças e limites obrigatórios

- A árvore dedicada pertence exclusivamente ao ensaio: sem mutação adversarial
  concorrente durante `lstat`/`realpath`/abertura. Componentes, DB e sidecars são
  verificados contra symlinks/junctions; arquivos com hard links também rejeitam.
  A identidade do DB é conferida antes/depois de abrir. A API Node RW **não**
  fornece abertura atômica existing-only; estes checks não eliminam TOCTOU.
- O nonce esperado é binding com o fornecedor do ensaio, **não** âncora antireplay
  externa. Replay de snapshot inteiro, válido e assinado não é detectável por
  este store sem uma âncora independente. Não se promete rejeição universal de
  corrupção/adulteração de WAL/SHM que resulte em snapshot válido anterior.
- WAL/FULL/EXCLUSIVE, integrity check, reopen e erro de I/O observados **não**
  provam durabilidade sob power loss, crash nem semântica universal de disco.
  Não há claim de segurança contra administrador/usuário que controla a árvore
  ou memória do processo, nem contra trocas concorrentes dos arquivos.
- O run Native acima mede Policy+store em Windows x64/NTFS. Não certifica
  download de instalador, Authenticode, NSIS, instalação, produção ou ativação.
  Nada nesta suíte transforma o canário Native de outro experimento em aceite
  desta Policy. A baseline permanece congelada, inclusive seu fsync de diretório
  e eventual EPERM no Windows: nenhum erro foi suprimido ou corrigido nela.
