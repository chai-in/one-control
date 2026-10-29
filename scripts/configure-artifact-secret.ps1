#Requires -Version 7.4
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$WranglerScript,
  [Parameter(Mandatory)][string]$ConfigurationFile,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$ExpectedAccountId,
  [Parameter(Mandatory)][string]$ExpectedWorkerName,
  [Parameter(Mandatory)][string]$ExpectedBucketName,
  [Parameter(Mandatory)][string]$ExpectedPublicHost,
  [string]$Root = (Join-Path $env:ProgramData 'OneControl\Artifacts')
)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'initialize-artifact-store.ps1') -Root $Root -ValidateOnly | Out-Null
. (Join-Path $PSScriptRoot 'lib\artifact-storage.ps1')
$store = Get-ArtifactStore $Root
$tool = (Resolve-Path -LiteralPath $WranglerScript).Path
$config = (Resolve-Path -LiteralPath $ConfigurationFile).Path
$configuration = Get-Content -Raw -LiteralPath $config | ConvertFrom-Json
if ($configuration.name -cne $ExpectedWorkerName -or $configuration.account_id -cne $ExpectedAccountId -or
    $configuration.vars.ARTIFACT_PUBLIC_HOST -cne $ExpectedPublicHost -or
    @($configuration.r2_buckets).Count -ne 1 -or $configuration.r2_buckets[0].binding -cne 'ARTIFACTS' -or
    $configuration.r2_buckets[0].bucket_name -cne $ExpectedBucketName -or
    ($env:CLOUDFLARE_ACCOUNT_ID -and $env:CLOUDFLARE_ACCOUNT_ID -cne $configuration.account_id)) { throw 'Artifact key configuration differs from the explicitly reviewed account, Worker, bucket or host.' }
# Wrangler reads the single download-only key from stdin. It never receives release or Authenticode keys.
$payload = @{ARTIFACT_READ_KEY=$store.Secret} | ConvertTo-Json -Compress
$payload | & node.exe $tool secret bulk --config $config
if ($LASTEXITCODE -ne 0) { throw 'Artifact Worker key configuration failed. Preserve the protected key and inspect the named Worker.' }
[pscustomobject]@{Worker=$ExpectedWorkerName;KeyId=$store.KeyId;Configured=$true}
