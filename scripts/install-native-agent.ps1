#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$BootstrapFile,
  [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$BootstrapSha256,
  [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$PublisherThumbprint,
  [Parameter(Mandatory)][string]$ConfigurationFile,
  [Parameter(Mandatory)][string]$InvitationFile
)
$ErrorActionPreference='Stop'
$serviceName='OneControlNative'
$installRoot=Join-Path $env:ProgramFiles 'OneControlNative'
$stateRoot=Join-Path $env:ProgramData 'OneControlNative'
$binary=Join-Path $installRoot 'oc-bootstrap.exe'
$configuration=Join-Path $stateRoot 'installation.json'
$invitation=Join-Path $stateRoot 'invitation.json'

function Assert-Release([string]$Path) {
  $item=Get-Item -LiteralPath $Path
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Bootstrap must be an ordinary file.'}
  if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $BootstrapSha256) {throw 'Bootstrap release hash mismatch.'}
  $signature=Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint) {throw 'Bootstrap publisher signature is not trusted.'}
}
function Invoke-Bootstrap([string[]]$Arguments) {
  & $binary @Arguments
  if ($LASTEXITCODE -ne 0) {throw 'Native bootstrap operation failed; preserve installation and credential state for reconciliation.'}
}

$BootstrapFile=(Resolve-Path -LiteralPath $BootstrapFile).Path
$ConfigurationFile=(Resolve-Path -LiteralPath $ConfigurationFile).Path
$InvitationFile=(Resolve-Path -LiteralPath $InvitationFile).Path
Assert-Release $BootstrapFile
if (Get-Service -Name 'OneControlAgent' -ErrorAction SilentlyContinue) {
  throw 'The imported policy agent is installed. Complete an explicit migration before installing the native agent.'
}
$existing=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
$command='"'+$binary+'" --config "'+$configuration+'" --service'
if ($existing -and ($existing.PathName -ne $command -or $existing.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM'))) {
  throw 'The native service registration differs; preserve it for reconciliation.'
}
if ($existing -and $existing.State -ne 'Stopped') {throw 'The native service is running; use its managed update path.'}

# The verified executable creates each directory with its final protected ACL.
& $BootstrapFile --prepare-root $installRoot
if ($LASTEXITCODE -ne 0) {throw 'Cannot create protected binary storage.'}
& $BootstrapFile --prepare-root $stateRoot
if ($LASTEXITCODE -ne 0) {throw 'Cannot create protected machine storage.'}
if (Test-Path -LiteralPath $binary) {Assert-Release $binary} else {
  Copy-Item -LiteralPath $BootstrapFile -Destination $binary
  Assert-Release $binary
}
if (Test-Path -LiteralPath $configuration) {
  if ((Get-FileHash -LiteralPath $configuration).Hash -ne (Get-FileHash -LiteralPath $ConfigurationFile).Hash) {throw 'Existing installation configuration differs; it cannot be replaced during enrollment.'}
} else {Copy-Item -LiteralPath $ConfigurationFile -Destination $configuration}
if ($InvitationFile -eq $invitation) {throw 'Supply the original invitation from outside the target runtime directory.'}
Copy-Item -LiteralPath $InvitationFile -Destination $invitation -Force
try {Invoke-Bootstrap @('--config',$configuration,'--enroll',$invitation)} finally {
  Remove-Item -LiteralPath $invitation -ErrorAction SilentlyContinue
}
if (!$existing) {
  New-Service -Name $serviceName -BinaryPathName $command -DisplayName 'One Control Native Bootstrap' -Description 'Device identity and selected signed module lifecycle' -StartupType Automatic | Out-Null
}
& sc.exe failure $serviceName reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'Cannot configure native service restart policy.'}
Start-Service -Name $serviceName
$deadline=[DateTime]::UtcNow.AddSeconds(60)
do {
  $statusFile=Join-Path $stateRoot 'status.json'
  if (Test-Path -LiteralPath $statusFile) {
    $status=Get-Content -LiteralPath $statusFile -Raw | ConvertFrom-Json
    if ($status.state -eq 'connected' -and [DateTime]$status.observedAt -gt $deadline.AddSeconds(-60)) {
      Write-Output 'Native service enrolled and connected. Optional features follow signed management selection.'
      return
    }
  }
  Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $deadline)
throw 'The service has not confirmed a fresh connection. Preserve its protected status and journals; do not enroll it again.'
