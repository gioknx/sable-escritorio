// Valores fixos do ensaio. Cada um vem de fonte nomeada na README desta pasta.
export const VERSIONS = Object.freeze({ floor: '2.2.1', seed: '2.2.2', target: '2.2.3' });
export const IDENTIFIER = 'moe.sable.client';
export const PRODUCT_EXE = 'Sable.exe';

// Bytes nativos publicados (published-native-identity.json da mãe); nunca recompilar Rust.
export const NATIVE = Object.freeze({
  sable_node: 'ef3d908e2941786e99f17520839968baa525861b743f7fb40494f84b7e4e362b',
  sable_audiofox: '275745eb3bc6fc6aca39ca0a4ccd39cb89afd4c019cf2bc6925977084205ad04',
});
export const PUBLISHED_INSTALLER_SHA256 = 'f4997c6857966947a60f8207aecbd21a39a497cb2ea2c2eb49ffc515549001a1';
export const RUST_SOURCE_ARCHIVE_SHA256 = '4b699d5a1e5d68dece7e34584bbe13009dd26230257650e385102acac042f58c';

// Mesmo pin do workflow Native já validado (gio-update-auth-windows native-nsis-windows.yml).
export const ELECTRON = Object.freeze({
  version: '45.0.0',
  archive: 'electron-v45.0.0-win32-x64.zip',
  archiveSha256: 'ae53887a23bb640369c93dbd38c408a2af5c0deb86f2fa76c6c244cb444b7f47',
});

// Fonte real lida em download-fonte/electron (sha256 medido em 2026-11-04). Mudou => revisar antes de rodar.
export const SOURCE_PINS = Object.freeze({
  'electron/build.mjs': '7057b86977a9a4f6a83aebd37343a1e7d9d3bb19b2948f987b562483e52964e3',
  'electron/after-pack.mjs': 'b55cf978b3943e2e77ac05c7bf19957571d1b5ab4a106a5b7051f0d07464bf77',
  'electron/office-config.mjs': '242d901940f4b7aecf91fee2103ffde212228303ad1a11a54263226058c7dcd8',
  // Pós-0015: builderSource() de ../gerar-patch-desktop-update.mjs aplicado ao original PRE_0015 (test/io.test recomputa).
  'electron/electron-builder.yml': 'db59a24b147a37f7f0cc266d3a6598fa023e56b9901b64335a2ae2624513f96e',
  'electron/electron-builder.stable.yml': '170321761cef6cd10781f276a2e342b483ac60a134fe12ed58b7884fd770cede',
  'scripts/build/csp.mjs': 'b7242f32505cc846c40c8f420a0089023d262a32b19a9a776e5417b296c4b98f',
});
export const PRE_0015_BUILDER_YML = '41b966f30085e896ed9c3a95a4f4fa0e07c75d4022c3c73e1d4002da7e9e1b4e';
// Layout da ponte consolidada pela mãe (patch 0015). Cada caminho deve existir e constar de recipe.sourceFiles.
export const CONSOLIDATED_LAYOUT = Object.freeze([
  'electron/src/main.ts', 'electron/src/updater.ts', 'electron/src/update-runtime-modules.d.ts',
  'electron/desktop-update/runtime/policy.cjs', 'electron/desktop-update/runtime/store.cjs',
  'electron/desktop-update/runtime/update-auth.cjs', 'electron/desktop-update/runtime/bootstrap.cjs',
]);
// Recurso lido do projectDir electron/ pelo extraResources do 0015 (sem arquivo = updates desligados).
export const UPDATES_RESOURCE = 'electron/mindtech-updates.json';
export const TOOL_VERSIONS = Object.freeze({
  'electron/node_modules/electron-builder': '26.18.0',
  'electron/node_modules/electron-updater': '6.8.11',
  'electron/node_modules/esbuild': '0.28.2',
  'electron/node_modules/electron': '45.0.0',
});

// Distro oficial: https://cloud-images.ubuntu.com/wsl/releases/24.04/20240423/SHA256SUMS (lido 2026-11-04).
export const WSL_ROOTFS = Object.freeze({
  url: 'https://cloud-images.ubuntu.com/wsl/releases/24.04/20240423/ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz',
  sha256: '2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934',
});
// Mesma versão da imagem Synapse do escritório (derivadas/synapse, v1.162.0); wheel exato do PyPI.
export const SYNAPSE = Object.freeze({
  version: '1.162.0',
  wheel: 'matrix_synapse-1.162.0-cp310-abi3-manylinux_2_28_x86_64.whl',
  wheelSha256: 'ea122be63a088f0e3993cf35019c9b6ca4a9baf0bc26019c4549317c5342ee99',
  serverName: 'escritorio.localhost',
  port: 8008,
  homeserver: 'http://escritorio.localhost:8008',
});
export const OFFICE_HOMESERVER = 'https://play.fablemedia.tech';
