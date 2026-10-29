#Requires -RunAsAdministrator
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('prepare','install','restart','cleanup')][string]$Action,
  [Parameter(Mandatory)][string]$FixtureDirectory,
  [string]$BootstrapFile,
  [string]$ConfigurationFile,
  [string]$InvitationFile
)
$ErrorActionPreference='Stop'
if ($env:CI -ne 'true' -or $env:ONE_CONTROL_NATIVE_ACCEPTANCE -ne 'true') {throw 'Service acceptance is restricted to the isolated Windows CI runner.'}
$serviceName='OneControlNative'
$stateRoot=Join-Path $env:ProgramData $serviceName
$binaryRoot=Join-Path $env:ProgramFiles $serviceName
$receipt=Join-Path $FixtureDirectory 'service-fixture.json'
if ($Action -eq 'prepare') {
  if ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $stateRoot) -or (Test-Path -LiteralPath $binaryRoot) -or (Test-Path -LiteralPath $receipt)) {throw 'Existing native installation or fixture must not be changed.'}
  $certificate=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=One Control isolated CI fixture' -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddHours(2)
  @{thumbprint=$certificate.Thumbprint;stateRoot=$stateRoot;binaryRoot=$binaryRoot} | ConvertTo-Json | Set-Content -LiteralPath $receipt
  foreach ($name in @('Root','TrustedPublisher')) {
    $store=[Security.Cryptography.X509Certificates.X509Store]::new($name,'LocalMachine')
    try {$store.Open('ReadWrite');$store.Add($certificate)} finally {$store.Dispose()}
  }
  $signature=Set-AuthenticodeSignature -LiteralPath $BootstrapFile -Certificate $certificate -HashAlgorithm SHA256
  if ($signature.Status -ne 'Valid') {throw 'Fixture signature failed.'}
  return
}
$owned=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
if ($owned.stateRoot -ne $stateRoot -or $owned.binaryRoot -ne $binaryRoot -or $owned.thumbprint -notmatch '^[A-Fa-f0-9]{40}$') {throw 'Invalid fixture custody record.'}
if ($Action -eq 'install') {
  & (Join-Path $PSScriptRoot '../install-native-agent.ps1') -BootstrapFile $BootstrapFile -BootstrapSha256 (Get-FileHash -LiteralPath $BootstrapFile -Algorithm SHA256).Hash -PublisherThumbprint $owned.thumbprint -ConfigurationFile $ConfigurationFile -InvitationFile $InvitationFile
  $service=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
  if ($service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or $service.State -ne 'Running') {throw 'Installed service is not running as SYSTEM.'}
  return
}
if ($Action -eq 'restart') {
  Stop-Service -Name $serviceName
  (Get-Service -Name $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))
  Start-Service -Name $serviceName
  return
}
$service=Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
  Stop-Service -Name $serviceName
  $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60))
  & sc.exe delete $serviceName | Out-Null
  if ($LASTEXITCODE -ne 0) {throw 'Cannot remove the owned fixture service.'}
}
foreach ($target in @($stateRoot,$binaryRoot)) {
  $absolute=[IO.Path]::GetFullPath($target)
  $expectedParent=if ($target -eq $stateRoot) {$env:ProgramData} else {$env:ProgramFiles}
  if ([IO.Path]::GetDirectoryName($absolute) -ne [IO.Path]::GetFullPath($expectedParent) -or [IO.Path]::GetFileName($absolute) -ne $serviceName) {throw 'Unexpected fixture cleanup target.'}
  if (Test-Path -LiteralPath $absolute) {Remove-Item -LiteralPath $absolute -Recurse -Force}
}
foreach ($store in @('Root','TrustedPublisher','My')) {
  $path="Cert:\LocalMachine\$store\$($owned.thumbprint)"
  if (Test-Path -LiteralPath $path) {Remove-Item -LiteralPath $path -Force}
}
Remove-Item -LiteralPath $receipt
