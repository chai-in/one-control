import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";

test("Windows artifact storage preserves keys and failures and rejects untrusted access and unsigned MSIs", {
  skip: process.platform !== "win32",
}, (context) => {
  const privilege = spawnSync(
    "pwsh.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); try { if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 }; exit 3 } finally { $identity.Dispose() }",
    ],
    { windowsHide: true, encoding: "utf8", timeout: 10_000 },
  );
  if (privilege.status === 3 && process.env.CI !== "true") {
    context.skip("Requires elevated Windows storage ownership; mandatory in the Windows CI job.");
    return;
  }
  assert.equal(
    privilege.status,
    0,
    "Windows CI requires an elevated account for protected storage acceptance.",
  );
  const source = String.raw`
$ErrorActionPreference = 'Stop'
. (Join-Path $env:ONE_CONTROL_ARTIFACT_TEST_REPO 'scripts\lib\artifact-storage.ps1')
$base = Join-Path $env:ProgramData 'OneControl.Artifact.Tests'
if (-not (Test-Path -LiteralPath $base)) { New-ArtifactPrivateDirectory $base }
Assert-ArtifactStoragePath -Path $base -Directory
$fixture = Join-Path $base ([Guid]::NewGuid().ToString('N'))
New-ArtifactPrivateDirectory $fixture
try {
  $initialize = Join-Path $env:ONE_CONTROL_ARTIFACT_TEST_REPO 'scripts\initialize-artifact-store.ps1'
  $storeRoot = Join-Path $fixture 'store'
  $first = & $initialize -Root $storeRoot
  $keyFile = Join-Path $storeRoot 'download-key.json'
  $before = (Get-FileHash -LiteralPath $keyFile -Algorithm SHA256).Hash
  $second = & $initialize -Root $storeRoot
  if ($first.KeyId -cne $second.KeyId -or $before -cne (Get-FileHash -LiteralPath $keyFile -Algorithm SHA256).Hash) { throw 'Initialization changed existing key bytes.' }
  $decoded = Get-ArtifactStore $storeRoot
  if ((Get-Content -Raw -LiteralPath $keyFile).Contains($decoded.Secret)) { throw 'Artifact key was stored in plaintext.' }
  $fakeMsi = Join-Path $storeRoot 'one-control-agent-0.2.3.msi'
  Write-ArtifactPrivateFile $fakeMsi 'Unsigned, non-executable fixture.'
  $refused = $false
  try { & (Join-Path $env:ONE_CONTROL_ARTIFACT_TEST_REPO 'scripts\issue-artifact-url.ps1') -Root $storeRoot -MsiFile $fakeMsi -PublisherThumbprint ('A'*40) -Origin 'https://artifacts.example.com' | Out-Null } catch { $refused = $true }
  if (-not $refused -or @(Get-ChildItem -LiteralPath $storeRoot -Filter 'read-authorization-*').Count -ne 0) { throw 'Unsigned artifact received download authority.' }
  $originalAcl = Get-Acl -LiteralPath $storeRoot
  try {
    $changed = Get-Acl -LiteralPath $storeRoot
    $changed.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','Allow'))
    Set-Acl -LiteralPath $storeRoot -AclObject $changed
    $refused = $false
    try { & $initialize -Root $storeRoot -ValidateOnly | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw 'Untrusted storage readers were accepted.' }
  } finally { Set-Acl -LiteralPath $storeRoot -AclObject $originalAcl }
  Set-Content -LiteralPath $keyFile -Value '{broken' -Encoding utf8
  $before = (Get-FileHash -LiteralPath $keyFile -Algorithm SHA256).Hash
  $refused = $false
  try { & $initialize -Root $storeRoot | Out-Null } catch { $refused = $true }
  if (-not $refused -or $before -cne (Get-FileHash -LiteralPath $keyFile -Algorithm SHA256).Hash) { throw 'Invalid key evidence was replaced.' }
  $partial = Join-Path $fixture 'partial'
  New-ArtifactPrivateDirectory $partial
  Write-ArtifactPrivateFile (Join-Path $partial 'evidence.txt') 'Interrupted initialization evidence.'
  $refused = $false
  try { & $initialize -Root $partial | Out-Null } catch { $refused = $true }
  if (-not $refused -or (Test-Path -LiteralPath (Join-Path $partial 'download-key.json'))) { throw 'Partial initialization was overwritten.' }
  [pscustomobject]@{idempotent=$true;dpapiProtected=$true;unsignedRejected=$true;untrustedAccessRejected=$true;invalidPreserved=$true;partialPreserved=$true} | ConvertTo-Json -Compress
} finally {
  $absolute = [IO.Path]::GetFullPath($fixture)
  if (-not [IO.Path]::GetDirectoryName($absolute).Equals([IO.Path]::GetFullPath($base),[StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup escaped isolated artifact fixtures.' }
  Assert-ArtifactStoragePath -Path $absolute -Directory
  if (@(Get-ChildItem -LiteralPath $absolute -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count -gt 0) { throw 'Preserve reparse-point fixture for inspection.' }
  Remove-Item -LiteralPath $absolute -Recurse -Force
}
`;
  const result = spawnSync(
    "pwsh.exe",
    ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(source, "utf16le").toString("base64")],
    {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
      env: { ...process.env, ONE_CONTROL_ARTIFACT_TEST_REPO: resolve(".") },
    },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    idempotent: true,
    dpapiProtected: true,
    unsignedRejected: true,
    untrustedAccessRejected: true,
    invalidPreserved: true,
    partialPreserved: true,
  });
});
