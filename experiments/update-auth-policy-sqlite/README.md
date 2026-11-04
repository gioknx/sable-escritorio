# Policy + SQLite: candidato isolado, somente core e UNIT

Esta fatia **não integra** `AuthenticatedNsisUpdater`, app, NSIS ou produção.
Não existe driver/coletor Native neste diretório. Policy + store **ainda não
foram executados no Electron/Windows Native**. PASS de UNIT/Node não autoriza
Native PASS, ativação ou instalação. O canário SQLite de outro experimento não
certifica esta Policy.

## API nova e dependências existentes

`policy.cjs` exporta `{ Policy }`, diferente da Policy privada em
`../update-auth-windows/update-auth.cjs`. Os helpers de validação, `decode`,
metadados congelados/WeakMap, `guard` e `rehash` preservam as regras desse núcleo.
Não há clock, expiração ou freshness novos, nem API preexistente `verifyEnvelope`.
Nenhum updater, download de instalador ou lançamento de processo é integrado.

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
for f in policy store test run-unit; do
  node --check experiments/update-auth-policy-sqlite/$f.cjs || exit 1
done
node experiments/update-auth-policy-sqlite/run-unit.cjs
node experiments/update-auth-windows/run-unit.cjs
node --test experiments/update-auth-sqlite/probe.test.cjs
git diff --check
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
- Esta entrega não executa Native Policy+store, não cria driver/coletor Native,
  não testa NTFS, download, Authenticode, NSIS, instalação, produção ou ativação.
  Nada nesta suíte transforma o canário Native de outro experimento em aceite
  desta Policy. A baseline permanece congelada, inclusive seu fsync de diretório
  e eventual EPERM no Windows: nenhum erro foi suprimido ou corrigido nela.
