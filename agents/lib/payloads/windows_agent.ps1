# =============================================================================
#  agents/lib/payloads/windows_agent.ps1 — exécuté SUR la cible Windows
#  (via WinRM ou OpenSSH, avec un compte administrateur).
#  Les variables $ACTION, $WAZUH_MANAGER, ... sont injectées en tête par
#  install-agent.sh. Compatible PowerShell 5.1.
#  Protocole de sortie : STEP|  INFO|  WARN|  KV|cle=valeur  RESULT|ok|...
# =============================================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Say($m)  { Write-Output "STEP|$m" }
function Info($m) { Write-Output "INFO|$m" }
function Warn($m) { Write-Output "WARN|$m" }
function KV($k, $v) { Write-Output ("KV|{0}={1}" -f $k, (("$v") -replace "[`r`n]+", ' ')) }
# Ok / Fail interrompent l'exécution par une exception interceptée en fin de
# script (pas de "exit" : incompatible avec une exécution PSRP/WinRM)
function Ok($m)   { throw "WZOK|$m" }
function Fail($m) { throw "WZFAIL|$m" }

Write-Output 'PAYLOAD_START'

$OssecDir = if (Test-Path "${env:ProgramFiles(x86)}\ossec-agent") { "${env:ProgramFiles(x86)}\ossec-agent" }
            elseif (Test-Path "$env:ProgramFiles\ossec-agent") { "$env:ProgramFiles\ossec-agent" }
            elseif ([Environment]::Is64BitOperatingSystem) { "${env:ProgramFiles(x86)}\ossec-agent" }
            else { "$env:ProgramFiles\ossec-agent" }
$OssecLog = Join-Path $OssecDir 'ossec.log'
$WorkDir  = Join-Path $env:SystemRoot 'Temp\wazuh-deploy'

function Test-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AgentUninstall {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
          'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  Get-ItemProperty $keys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like 'Wazuh Agent*' } | Select-Object -First 1
}

function Test-Tcp($h, $port) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($h, $port, $null, $null)
    $okc = $iar.AsyncWaitHandle.WaitOne(4000, $false) -and $c.Connected
    $c.Close()
    return $okc
  } catch { return $false }
}

function Get-Package {
  New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
  $script:Msi = Join-Path $WorkDir $PKG_FILE
  if ($PKG_LOCAL -and (Test-Path $PKG_LOCAL)) {
    Move-Item -Force $PKG_LOCAL $script:Msi
    Say "Paquet reçu du serveur ($PKG_FILE)"
  } else {
    Say "Téléchargement $PKG_URL"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try { Invoke-WebRequest -Uri $PKG_URL -OutFile $script:Msi -UseBasicParsing }
    catch { Fail "téléchargement impossible : $PKG_URL ($($_.Exception.Message))" }
  }
  if (-not (Test-Path $script:Msi) -or (Get-Item $script:Msi).Length -eq 0) { Fail 'paquet vide ou absent' }
}

function Wait-Connected($seconds) {
  for ($i = 0; $i -lt $seconds; $i += 3) {
    if ((Test-Path $OssecLog) -and (Select-String -Path $OssecLog -Pattern 'Connected to the server' -Quiet)) { return $true }
    Start-Sleep -Seconds 3
  }
  return $false
}

function Invoke-Msi($arguments) {
  $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
  return $p.ExitCode
}

try {
  if (-not (Test-Admin)) { Fail 'le compte utilisé n''est pas administrateur (ou UAC distant : voir active-winRm.ps1)' }

  switch ($ACTION) {
    'facts' {
      $os = Get-CimInstance Win32_OperatingSystem
      KV 'OS_KERNEL' 'Windows'
      KV 'OS_NAME' $os.Caption
      KV 'ARCH' $env:PROCESSOR_ARCHITECTURE
      KV 'HOSTNAME' $env:COMPUTERNAME
      KV 'PKG_TYPE' 'msi'
      KV 'PKG_MANAGER' 'msiexec'
      KV 'FREE_MB' ([int]((Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1MB))
      $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
      $un = Get-AgentUninstall
      if ($svc -or $un) {
        KV 'AGENT_INSTALLED' 'yes'
        KV 'WAZUH_TYPE' 'agent'
        if ($un) { KV 'AGENT_VERSION' $un.DisplayVersion }
        KV 'AGENT_RUNNING' $(if ($svc -and $svc.Status -eq 'Running') { 'yes' } else { 'no' })
        $keys = Join-Path $OssecDir 'client.keys'
        if ((Test-Path $keys) -and (Get-Item $keys).Length -gt 0) {
          $f = (Get-Content $keys -TotalCount 1).Split(' ')
          KV 'AGENT_ID' $f[0]; KV 'AGENT_NAME' $f[1]
        }
      } else { KV 'AGENT_INSTALLED' 'no' }
      KV 'PORT_1514' $(if (Test-Tcp $WAZUH_MANAGER 1514) { 'ok' } else { 'ko' })
      KV 'PORT_1515' $(if (Test-Tcp $WAZUH_MANAGER 1515) { 'ok' } else { 'ko' })
      if ($CHECK_INTERNET -eq 'yes') {
        $h = ([Uri]$PKG_BASE_URL).Host
        KV 'INTERNET' $(if (Test-Tcp $h 443) { 'ok' } else { 'ko' })
      }
      Ok 'facts'
    }

    'install' {
      Get-Package
      Say "Installation MSI (manager $WAZUH_MANAGER, groupe $WAZUH_AGENT_GROUP, nom $WAZUH_AGENT_NAME)"
      $log = Join-Path $WorkDir 'wazuh-msi.log'
      $a = "/i `"$script:Msi`" /qn /l*v `"$log`" WAZUH_MANAGER=`"$WAZUH_MANAGER`" " +
           "WAZUH_REGISTRATION_PASSWORD=`"$ENROLL_PASS`" WAZUH_AGENT_GROUP=`"$WAZUH_AGENT_GROUP`" " +
           "WAZUH_AGENT_NAME=`"$WAZUH_AGENT_NAME`""
      $rc = Invoke-Msi $a
      if ($rc -ne 0 -and $rc -ne 3010) { Fail "msiexec a échoué (code $rc, journal $log)" }
      Info "Paquet installé : $((Get-AgentUninstall).DisplayVersion)"
      Say 'Démarrage du service WazuhSvc'
      Start-Service -Name WazuhSvc
      Say 'Attente de la connexion au manager...'
      if (Wait-Connected 60) {
        $keys = Join-Path $OssecDir 'client.keys'
        if (Test-Path $keys) { KV 'AGENT_ID' ((Get-Content $keys -TotalCount 1).Split(' ')[0]) }
        Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
        Ok 'agent installé, enrôlé et connecté'
      }
      Get-Content $OssecLog -Tail 50 -ErrorAction SilentlyContinue | Select-String 'ERROR|authd|enrollment' |
        Select-Object -Last 3 | ForEach-Object { Warn $_.Line }
      Ok 'agent installé et démarré (connexion non confirmée côté agent)'
    }

    'update' {
      $un = Get-AgentUninstall
      if (-not $un) { Fail 'aucun agent installé' }
      $before = $un.DisplayVersion
      Get-Package
      Say "Mise à jour $before → $WAZUH_VERSION"
      $rc = Invoke-Msi "/i `"$script:Msi`" /qn /l*v `"$(Join-Path $WorkDir 'wazuh-msi-update.log')`""
      if ($rc -ne 0 -and $rc -ne 3010) { Fail "msiexec a échoué (code $rc)" }
      Restart-Service -Name WazuhSvc -ErrorAction SilentlyContinue
      $after = (Get-AgentUninstall).DisplayVersion
      KV 'AGENT_VERSION' $after
      Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
      Ok "agent mis à jour ($before → $after)"
    }

    { $_ -in 'remove', 'purge' } {
      $un = Get-AgentUninstall
      if (-not $un -and -not (Get-Service WazuhSvc -ErrorAction SilentlyContinue)) {
        if ($ACTION -eq 'purge' -and (Test-Path $OssecDir)) { Remove-Item -Recurse -Force $OssecDir }
        Ok 'aucun agent installé'
      }
      Say 'Arrêt du service WazuhSvc'
      Stop-Service -Name WazuhSvc -Force -ErrorAction SilentlyContinue
      Say 'Désinstallation MSI'
      if ($un.PSChildName -match '^\{.*\}$') {
        $rc = Invoke-Msi "/x $($un.PSChildName) /qn"
      } else {
        $rc = Invoke-Msi "/x `"$($un.UninstallString -replace '(?i)msiexec\.exe\s*/[IX]\s*','')`" /qn"
      }
      if ($rc -ne 0 -and $rc -ne 3010 -and $rc -ne 1605) { Fail "désinstallation échouée (code $rc)" }
      if ($ACTION -eq 'purge') {
        Say 'Purge des fichiers résiduels'
        if (Test-Path $OssecDir) { Remove-Item -Recurse -Force $OssecDir -ErrorAction SilentlyContinue }
        Ok 'agent désinstallé et purgé'
      }
      Ok 'agent désinstallé'
    }

    'status' {
      $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
      if (-not $svc) { KV 'AGENT_INSTALLED' 'no'; Ok 'aucun agent installé' }
      KV 'AGENT_INSTALLED' 'yes'
      KV 'AGENT_VERSION' (Get-AgentUninstall).DisplayVersion
      KV 'AGENT_RUNNING' $(if ($svc.Status -eq 'Running') { 'yes' } else { 'no' })
      $last = Get-Content $OssecLog -ErrorAction SilentlyContinue |
        Select-String 'Connected to the server|Unable to connect|Lost connection|ERROR' | Select-Object -Last 1
      if ($last) { KV 'LAST_EVENT' $last.Line }
      Ok 'status'
    }

    'log' {
      if (-not (Test-Path $OssecLog)) { Fail "journal introuvable ($OssecLog)" }
      Get-Content $OssecLog -Tail $LOG_LINES | ForEach-Object { Write-Output "LOG|$_" }
      Ok 'log'
    }

    default { Fail "action inconnue : $ACTION" }
  }
} catch {
  $msg = $_.Exception.Message
  if ($msg.StartsWith('WZOK|'))       { Write-Output ('RESULT|ok|' + $msg.Substring(5)) }
  elseif ($msg.StartsWith('WZFAIL|')) { Write-Output ('RESULT|fail|' + $msg.Substring(7)) }
  else { Write-Output ('RESULT|fail|erreur PowerShell : ' + $msg) }
}
