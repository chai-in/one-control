[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ReleaseDirectory,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$PublisherThumbprint,
  [Parameter(Mandatory)][string]$SignTool,
  [ValidateSet('LocalMachine','CurrentUser')][string]$CertificateStore = 'LocalMachine',
  [uri]$TimestampServer = 'http://timestamp.digicert.com',
  [switch]$InternalTestSigning
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$tool = (Resolve-Path -LiteralPath $SignTool).Path
if ($TimestampServer.Scheme -notin 'http','https' -or $TimestampServer.UserInfo -or $TimestampServer.Query -or $TimestampServer.Fragment) { throw 'A timestamp endpoint without credentials or query parameters is required.' }
$toolSignature = Get-AuthenticodeSignature -LiteralPath $tool
if ($toolSignature.Status -ne 'Valid' -or $toolSignature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw 'SignTool must have a valid Microsoft signature.' }
$certificate = Get-Item -LiteralPath ('Cert:\'+$CertificateStore+'\My\'+$PublisherThumbprint)
if (-not $certificate.HasPrivateKey -or $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date) -or
    '1.3.6.1.5.5.7.3.3' -notin @($certificate.EnhancedKeyUsageList.ObjectId)) { throw 'A current code-signing certificate with its private key is required.' }
if (-not $InternalTestSigning) {
  if ($certificate.Subject -eq $certificate.Issuer) { throw 'Self-signed certificates are restricted to explicit internal test signing.' }
  $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
  try {
    $chain.ChainPolicy.RevocationMode = 'Online'
    $chain.ChainPolicy.RevocationFlag = 'ExcludeRoot'
    $chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    if (-not $chain.Build($certificate)) { throw 'Production signing certificate chain or revocation check failed.' }
  } finally { $chain.Dispose() }
}
$files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object Extension -In '.exe','.dll','.ps1','.msi')
if ($files.Count -eq 0) { throw 'Release has no signable files.' }
foreach ($entry in @(Get-Item -LiteralPath $root) + @(Get-ChildItem -LiteralPath $root -Recurse -Force)) {
  if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Signing input cannot traverse reparse points.' }
}
$dependencies = @()
foreach ($file in $files) {
  $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
  $owned = $file.Name -like 'OneControl.Agent.*' -or $file.Extension -in '.ps1','.msi'
  # Preserve a valid vendor signature rather than replacing its publisher identity.
  if (-not $owned -and $signature.Status -eq 'Valid') { $dependencies += $signature.SignerCertificate.Thumbprint; continue }
  # Re-running verification must not change already signed release bytes or their timestamp.
  if ($owned -and $signature.Status -eq 'Valid' -and $signature.SignerCertificate.Thumbprint -eq $PublisherThumbprint -and $signature.TimeStamperCertificate) {
    & $tool verify /pa /all /tw $file.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('Existing signature verification failed: '+$file.Name) }
    continue
  }
  $arguments = @('sign','/fd','SHA256','/sha1',$PublisherThumbprint,'/s','My','/tr',$TimestampServer.AbsoluteUri,'/td','SHA256')
  if ($CertificateStore -eq 'LocalMachine') { $arguments += '/sm' }
  # SignTool's RFC 3161 response is independently signature-verified, including over its documented HTTP endpoint.
  & $tool @arguments $file.FullName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw ('Signing or timestamping failed: '+$file.Name) }
  $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint -or -not $signature.TimeStamperCertificate) {
    throw ('Signed publisher/timestamp verification failed: '+$file.Name)
  }
  & $tool verify /pa /all /tw $file.FullName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw ('Independent signature verification failed: '+$file.Name) }
}
$record = [ordered]@{
  schemaVersion = 1
  signingMode = $(if ($InternalTestSigning) { 'internal_test' } else { 'production_certificate' })
  publisherThumbprint = $PublisherThumbprint.ToUpperInvariant()
  dependencyPublisherThumbprints = @($dependencies | Sort-Object -Unique)
  timestampServer = $TimestampServer.AbsoluteUri
  signedAt = [DateTime]::UtcNow.ToString('o')
  files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object Name -NotIn 'checksums.json','signing.json' | Sort-Object FullName | ForEach-Object {
    [ordered]@{path=$_.FullName.Substring($root.Length+1);size=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
  })
}
$record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'signing.json') -Encoding utf8
# Hash the final signed bytes. Pre-signing checksums are not release checksums.
$record.files | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'checksums.json') -Encoding utf8
[pscustomobject]@{signingMode=$record.signingMode;publisher=$record.publisherThumbprint;signedFiles=$files.Count;release=$root}
