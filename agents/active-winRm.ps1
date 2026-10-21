<#
=============================================================================
  active-winRm.ps1 — Prépare un poste/serveur Windows pour le déploiement
  à distance de l'agent Wazuh par install-agent.sh (WinRM).
  À exécuter UNE FOIS par machine, en administrateur (ou par GPO / script
  de démarrage).

  Ce que fait le script :
    1. Active PowerShell Remoting / WinRM (service démarré automatiquement)
    2. Ouvre le pare-feu Windows sur 5985 (et 5986 avec -Https), limité à
       l'IP du serveur Wazuh si -WazuhServer est fourni
    3. Autorise les comptes administrateurs LOCAUX à distance
       (LocalAccountTokenFilterPolicy = 1, nécessaire hors domaine)
    4. Optionnel (-Https) : écouteur HTTPS 5986 avec certificat auto-signé

  Exemples :
    powershell -ExecutionPolicy Bypass -File .\active-winRm.ps1 -WazuhServer 192.168.1.5
    powershell -ExecutionPolicy Bypass -File .\active-winRm.ps1 -WazuhServer 192.168.1.5 -Https
    powershell -ExecutionPolicy Bypass -File .\active-winRm.ps1 -Disable      # retour arrière
=============================================================================
#>
[CmdletBinding()]
param(
  # IP (ou sous-réseau) du serveur Wazuh autorisé à se connecter. Vide = toutes.
  [string]$WazuhServer = '',
  # Ajoute un écouteur HTTPS (5986) avec certificat auto-signé
  [switch]$Https,
  # Désactive ce que le script a activé
  [switch]$Disable
)

$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Done($m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Ce script doit être lancé en tant qu'administrateur." -ForegroundColor Red
  exit 1
}

$ruleHttp  = 'Wazuh-Deploy WinRM HTTP (5985)'
$ruleHttps = 'Wazuh-Deploy WinRM HTTPS (5986)'
$policyKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

if ($Disable) {
  Step 'Retrait des règles de pare-feu Wazuh-Deploy'
  Get-NetFirewallRule -DisplayName 'Wazuh-Deploy*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Step 'Suppression de l''écouteur HTTPS éventuel'
  Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  Step 'Restauration de LocalAccountTokenFilterPolicy'
  Remove-ItemProperty -Path $policyKey -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
  Step 'Désactivation de PowerShell Remoting'
  Disable-PSRemoting -Force
  Stop-Service WinRM -ErrorAction SilentlyContinue
  Set-Service WinRM -StartupType Manual
  Done 'WinRM désactivé.'
  exit 0
}

Step 'Activation de PowerShell Remoting (WinRM)'
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
# Pas de trafic non chiffré ni d'authentification Basic
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Done 'WinRM actif (HTTP 5985, messages chiffrés NTLM/Kerberos)'

Step 'Comptes administrateurs locaux autorisés à distance (LocalAccountTokenFilterPolicy=1)'
New-ItemProperty -Path $policyKey -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
Done 'UAC distant configuré'

$remote = if ($WazuhServer) { $WazuhServer } else { 'Any' }
Step "Pare-feu : autorisation du port 5985 depuis $remote"
Get-NetFirewallRule -DisplayName $ruleHttp -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $ruleHttp -Direction Inbound -Protocol TCP -LocalPort 5985 `
  -RemoteAddress $remote -Profile Any -Action Allow | Out-Null
Done 'Règle de pare-feu HTTP créée'

if ($Https) {
  Step 'Création d''un certificat auto-signé et d''un écouteur HTTPS (5986)'
  $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
  $cert = New-SelfSignedCertificate -DnsName $fqdn, $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My `
            -NotAfter (Get-Date).AddYears(5)
  Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
  Get-NetFirewallRule -DisplayName $ruleHttps -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  New-NetFirewallRule -DisplayName $ruleHttps -Direction Inbound -Protocol TCP -LocalPort 5986 `
    -RemoteAddress $remote -Profile Any -Action Allow | Out-Null
  Done "Écouteur HTTPS actif (certificat $($cert.Thumbprint)) — utilisez --win-https"
}

Step 'Vérification'
Test-WSMan -ComputerName localhost | Out-Null
Done 'WinRM répond localement'
Write-Host ''
Write-Host 'Ce poste est prêt. Depuis le serveur Wazuh :' -ForegroundColor Green
Write-Host "  ./agents/install-agent.sh <IP_DE_CE_POSTE> -w -u <ADMIN> -p" -ForegroundColor Green
if (-not $WazuhServer) { Warn 'Conseil : relancez avec -WazuhServer <IP> pour restreindre l''accès WinRM au seul serveur Wazuh.' }
