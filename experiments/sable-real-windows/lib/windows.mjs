import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
// Scripts PowerShell recebem dados só por variáveis de ambiente ENSAIO_*; nunca concatenação no texto.
export const PS = Object.freeze({
  volume: `$ErrorActionPreference='Stop'; $d=[IO.Path]::GetPathRoot($env:ENSAIO_PATH).Substring(0,1); (Get-Volume -DriveLetter $d).FileSystem`,
  // Qualquer Sable vivo ou instalado antes do ensaio: o fallback NSIS por nome/usuário tornaria o escopo ambíguo.
  foreignSable: `$ErrorActionPreference='Stop'
$p=@(Get-CimInstance Win32_Process -Filter "Name='Sable.exe'" | ForEach-Object { [int]$_.ProcessId })
$u=@(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Sable*' } | ForEach-Object { $_.PSChildName })
ConvertTo-Json -Compress -InputObject @{processes=$p;uninstall=$u}`,
  uninstallEntry: `$ErrorActionPreference='Stop'
$e=@(Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Sable*' } | ForEach-Object { @{key=$_.PSChildName;displayVersion=$_.DisplayVersion;installLocation=$_.InstallLocation} })
ConvertTo-Json -Compress -Depth 3 -InputObject $e`,
  peVersion: `$ErrorActionPreference='Stop'; $v=(Get-Item -LiteralPath $env:ENSAIO_PATH).VersionInfo; ConvertTo-Json -Compress -InputObject @{file=$v.FileVersion;product=$v.ProductVersion}`,
  // Término abrupto (TerminateProcess) só de PID observado cuja imagem está dentro da raiz própria.
  stopOwned: `$ErrorActionPreference='Stop'; $done=@()
foreach($id in ($env:ENSAIO_PIDS -split ',')){ $p=Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$id)"; if($p -and $p.ExecutablePath -and $p.ExecutablePath.StartsWith($env:ENSAIO_ROOT,[StringComparison]::OrdinalIgnoreCase)){ Stop-Process -Id ([int]$id) -Force; $done+=[int]$id } }
ConvertTo-Json -Compress -InputObject @($done)`,
  ownedProcesses: `$ErrorActionPreference='Stop'
$r=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($env:ENSAIO_ROOT,[StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { @{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;executable=$_.ExecutablePath;commandLine=$_.CommandLine} })
ConvertTo-Json -Compress -Depth 3 -InputObject $r`,
  hostsAdd: `$ErrorActionPreference='Stop'; $h=Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'
$t=[IO.File]::ReadAllText($h); if($t -match '(?m)^\\s*[^#\\s]+\\s+escritorio\\.localhost\\b'){ throw 'hosts already maps escritorio.localhost' }
[IO.File]::AppendAllText($h, [Environment]::NewLine + '127.0.0.1 escritorio.localhost # sable-ensaio ' + $env:ENSAIO_NONCE + [Environment]::NewLine)`,
  hostsRemove: `$ErrorActionPreference='Stop'; $h=Join-Path $env:SystemRoot 'System32\\drivers\\etc\\hosts'
$l=[IO.File]::ReadAllLines($h) | Where-Object { $_ -notlike ('*# sable-ensaio ' + $env:ENSAIO_NONCE) }; [IO.File]::WriteAllLines($h, $l)`,
  // CA própria da execução no Root da máquina descartável: o download do electron-updater usa Electron net (Chromium),
  // que valida pela loja do Windows. Remoção pelo thumbprint no finally. Não é bypass: cadeia e hostname continuam verificados.
  caAdd: `$ErrorActionPreference='Stop'; $c=Import-Certificate -FilePath $env:ENSAIO_CA -CertStoreLocation Cert:\\LocalMachine\\Root; $c.Thumbprint`,
  caRemove: `$ErrorActionPreference='Stop'; if($env:ENSAIO_THUMB -notmatch '^[0-9A-F]{40}$'){ throw 'thumbprint' }; Remove-Item -LiteralPath ('Cert:\\LocalMachine\\Root\\' + $env:ENSAIO_THUMB)`,
  resolve: `$ErrorActionPreference='Stop'; ConvertTo-Json -Compress -InputObject @([Net.Dns]::GetHostAddresses('escritorio.localhost') | ForEach-Object { $_.ToString() })`,
  // Observador: amostra CIM a cada 100 ms; segura handle do instalador para obter o exit code real.
  // Para o app reaberto com --updated: hash da imagem e fatos do pai real (imagem, criação, SID, sessão, Authenticode),
  // só leitura; brokers do shell nunca são tocados.
  watcher: `$ErrorActionPreference='Stop'; $seen=@{}; $handles=@{}
function Emit($o){ Add-Content -LiteralPath $env:ENSAIO_LOG -Value (ConvertTo-Json -Compress -Depth 3 -InputObject $o) }
function Sid($c){ try { (Invoke-CimMethod -InputObject $c -MethodName GetOwnerSid).Sid } catch { $null } }
function Sha($path,$alg){ $s=[IO.File]::OpenRead($path); try { $h=[Security.Cryptography.HashAlgorithm]::Create($alg).ComputeHash($s) } finally { $s.Dispose() }; $h }
while(-not (Test-Path -LiteralPath $env:ENSAIO_STOP)){
  foreach($p in Get-CimInstance Win32_Process){
    $exe=$p.ExecutablePath; if(-not $exe){ continue }
    if(-not ($exe.StartsWith($env:ENSAIO_ROOT,[StringComparison]::OrdinalIgnoreCase) -or $p.Name -eq 'Sable.exe')){ continue }
    $key="$($p.ProcessId):$($p.CreationDate.Ticks)"; if($seen.ContainsKey($key)){ continue }; $seen[$key]=$true
    $row=@{kind='process';pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;executable=$exe;commandLine=$p.CommandLine;created=$p.CreationDate.ToUniversalTime().ToString('o');sid=(Sid $p);sessionId=[int]$p.SessionId}
    if($p.Name -eq 'Sable.exe' -and $p.CommandLine -match '(^|\\s)--updated(\\s|$)' -and $p.CommandLine -notmatch '\\s--type='){
      try { $row.sha256=[BitConverter]::ToString((Sha $exe 'SHA256')).Replace('-','').ToLowerInvariant() } catch { $row.hashError=$_.Exception.Message }
      $pp=Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$p.ParentProcessId)"
      if($pp -and $pp.ExecutablePath){ $sig=Get-AuthenticodeSignature -LiteralPath $pp.ExecutablePath
        $row.parentFacts=@{pid=[int]$pp.ProcessId;executable=$pp.ExecutablePath;created=$pp.CreationDate.ToUniversalTime().ToString('o');sid=(Sid $pp);sessionId=[int]$pp.SessionId;signatureStatus=[string]$sig.Status;signer=[string]$sig.SignerCertificate.Subject} }
    }
    if($exe.StartsWith($env:ENSAIO_CACHE,[StringComparison]::OrdinalIgnoreCase)){ try { $h=Get-Process -Id $p.ProcessId; $null=$h.Handle; $handles[[int]$p.ProcessId]=$h; $row.sha512=[Convert]::ToBase64String([Security.Cryptography.SHA512]::Create().ComputeHash([IO.File]::ReadAllBytes($exe))) } catch { $row.handleError=$_.Exception.Message } }
    Emit $row
  }
  foreach($id in @($handles.Keys)){ $h=$handles[$id]; if($h.HasExited){ Emit @{kind='exit';pid=$id;exitCode=$h.ExitCode;exitedAt=$h.ExitTime.ToUniversalTime().ToString('o')}; $handles.Remove($id) } }
  Start-Sleep -Milliseconds 100
}`,
});

export async function pwsh(script, env, timeout = 60000) {
  const { stdout } = await run('pwsh', ['-NoProfile', '-NonInteractive', '-Command', script], { env, timeout, maxBuffer: 1 << 22, windowsHide: true });
  return stdout.trim();
}
export async function pwshJson(script, env, timeout) {
  const out = await pwsh(script, env, timeout);
  return out ? JSON.parse(out) : null;
}
export function startWatcher(env) {
  return spawn('pwsh', ['-NoProfile', '-NonInteractive', '-Command', PS.watcher], { env, stdio: 'ignore', windowsHide: true });
}

// Lê o JSONL do observador; linha parcial final é ignorada (ainda sendo escrita).
export function parseWatcherLog(text) {
  const rows = [], exits = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let value;
    try { value = JSON.parse(line); } catch { continue; }
    if (value.kind === 'process') rows.push(value);
    else if (value.kind === 'exit') exits.set(value.pid, { exitCode: value.exitCode, exitedAt: value.exitedAt });
  }
  return { rows, exits };
}
