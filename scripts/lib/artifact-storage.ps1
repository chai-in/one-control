# Artifact-specific names retain the administration helper contract; protection is shared.
. (Join-Path $PSScriptRoot 'private-storage.ps1')
function Assert-ArtifactStoragePath {
  param([Parameter(Mandatory)][string]$Path,[switch]$Directory,[switch]$ParentOnly)
  Assert-PrivateStoragePath @PSBoundParameters
}
function New-ArtifactPrivateDirectory([string]$Path) { New-PrivateStorageDirectory $Path }
function Write-ArtifactPrivateFile([string]$Path,[string]$Content) { Write-PrivateStorageFile $Path $Content }
function Get-ArtifactStore([string]$Root) {
  $absolute = [IO.Path]::GetFullPath($Root)
  Assert-ArtifactStoragePath -Path $absolute -Directory
  $path = Join-Path $absolute 'download-key.json'
  Assert-ArtifactStoragePath -Path $path
  if ((Get-Item -LiteralPath $path).Length -gt 4096) { throw 'Artifact key record exceeds its size bound.' }
  $value = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
  if (@($value.PSObject.Properties).Count -ne 4 -or $value.schemaVersion -ne 1 -or $value.root -cne $absolute -or
      $value.keyId -cnotmatch '^[a-f0-9]{64}$' -or $value.protectedKey -cnotmatch '^[A-Za-z0-9+/=]{1,2048}$') { throw 'Invalid protected artifact key record; preserve it.' }
  $key = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($value.protectedKey),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
  if ($key.Length -ne 32 -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($key)).ToLowerInvariant() -cne $value.keyId) { throw 'Artifact key identity mismatch.' }
  [pscustomobject]@{Root=$absolute;KeyId=$value.keyId;Secret=[Convert]::ToBase64String($key).TrimEnd('=').Replace('+','-').Replace('/','_')}
}
