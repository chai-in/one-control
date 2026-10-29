#Requires -Version 7.4
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$MsiFile,
  [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{40}$')][string]$PublisherThumbprint,
  [string]$Root = (Join-Path $env:ProgramData 'OneControl\Artifacts'),
  [Parameter(Mandatory)][string]$Origin,
  [ValidateRange(1,1440)][int]$ExpiresMinutes = 60
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'initialize-artifact-store.ps1') -Root $Root -ValidateOnly | Out-Null
. (Join-Path $PSScriptRoot 'lib\artifact-storage.ps1')
$store = Get-ArtifactStore $Root
$file = Get-Item -LiteralPath $MsiFile -Force
if ($file.PSIsContainer -or $file.Attributes -band [IO.FileAttributes]::ReparsePoint -or
    $file.Name -cnotmatch '^one-control-agent-((?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,4}))\.msi$') { throw 'Select an exact versioned signed agent MSI.' }
$version = $Matches[1]
$locked = [IO.FileStream]::new($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
  $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $PublisherThumbprint -or -not $signature.TimeStamperCertificate) { throw 'Artifact publisher or timestamp validation failed.' }
  $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($locked)).ToLowerInvariant()
  $expires = [DateTimeOffset]::UtcNow.AddMinutes($ExpiresMinutes)
  $artifact = @{origin=$Origin;sha256=$sha;version=$version;size=$locked.Length;expires=$expires.ToUnixTimeSeconds()}
  $inputJson = @{secret=$store.Secret;artifact=$artifact} | ConvertTo-Json -Depth 4 -Compress
  $resultText = $inputJson | & node.exe (Join-Path $PSScriptRoot 'lib\issue-artifact-url.mjs')
  if ($LASTEXITCODE -ne 0) { throw 'Artifact URL issuance failed; no release was registered.' }
  $authorization = $resultText | ConvertFrom-Json
  $destination = Join-Path $store.Root ('read-authorization-'+[Guid]::NewGuid().ToString('N')+'.json')
  Write-ArtifactPrivateFile $destination ($authorization | ConvertTo-Json -Depth 4)
  [pscustomobject]@{AuthorizationFile=$destination;Sha256=$sha;Bytes=$locked.Length;ExpiresAt=$expires;Origin=$Origin;KeyId=$store.KeyId}
} finally { $locked.Dispose() }
