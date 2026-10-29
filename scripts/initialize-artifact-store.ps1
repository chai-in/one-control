#Requires -Version 7.4
[CmdletBinding()]
param([string]$Root = (Join-Path $env:ProgramData 'OneControl\Artifacts'),[switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or -not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated Windows artifact administration is required.' }
. (Join-Path $PSScriptRoot 'lib\artifact-storage.ps1')
$storage = [IO.Path]::GetFullPath($Root)
if (-not (Test-Path -LiteralPath $storage)) {
  if ($ValidateOnly) { throw 'Artifact storage is not initialized.' }
  New-ArtifactPrivateDirectory $storage
}
Assert-ArtifactStoragePath -Path $storage -Directory
$file = Join-Path $storage 'download-key.json'
if (-not (Test-Path -LiteralPath $file)) {
  if ($ValidateOnly -or @(Get-ChildItem -LiteralPath $storage -Force).Count -gt 0) { throw 'Artifact initialization is incomplete; preserve existing evidence.' }
  $key = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
  $protected = [Security.Cryptography.ProtectedData]::Protect($key,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
  $record = [ordered]@{schemaVersion=1;root=$storage;keyId=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($key)).ToLowerInvariant();protectedKey=[Convert]::ToBase64String($protected)}
  Write-ArtifactPrivateFile $file ($record | ConvertTo-Json)
}
$store = Get-ArtifactStore $storage
[pscustomobject]@{Root=$store.Root;KeyId=$store.KeyId;Validated=$true}
