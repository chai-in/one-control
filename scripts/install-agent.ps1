[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ReleaseDirectory,
  [Parameter(Mandatory)][string]$EnrollmentFile,
  [Parameter(Mandatory)][string]$ReleasePublicKeyFile,
  [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$PublisherThumbprint,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string[]]$DependencyPublisherThumbprints = @()
)
$ErrorActionPreference = 'Stop'
function Assert-ProtectedDirectory([string]$Path, [bool]$PrivateLeaf = $false, [bool]$AllowChildCreation = $false) {
  $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  $current = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
  $leaf = $true
  if ($current.FullName.StartsWith('\\')) { throw 'Local protected storage required.' }
  while ($null -ne $current) {
    if (-not $current.Exists -or ($current.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Protected path is missing or traverses a reparse point.' }
    $acl = Get-Acl -LiteralPath $current.FullName
    if ($null -eq ([Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)).DiscretionaryAcl) { throw 'Protected directory has an unrestricted DACL.' }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Untrusted directory owner. IT must reconcile existing state.' }
    $forbidden = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($leaf -and -not $AllowChildCreation) {
      $forbidden = $forbidden -bor [Security.AccessControl.FileSystemRights]::Write
      if ($PrivateLeaf) { $forbidden = [Security.AccessControl.FileSystemRights]::FullControl }
    }
    $genericForbidden = 0x50000000L
    if ($leaf -and $PrivateLeaf -and -not $AllowChildCreation) { $genericForbidden = 0xF0000000L }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
      if ($rule.IdentityReference.Value -in $trusted) { continue }
      if (($rule.FileSystemRights -band $forbidden) -or (([long]$rule.FileSystemRights -band $genericForbidden) -ne 0)) { throw 'Untrusted access to protected directory. IT must reconcile existing state.' }
    }
    $leaf = $false
    $current = $current.Parent
  }
}
function New-ProtectedDirectory([string]$Path, [bool]$PrivateLeaf = $false) {
  if (Test-Path -LiteralPath $Path) { Assert-ProtectedDirectory $Path $PrivateLeaf; return }
  $parent = Split-Path -Parent $Path
  Assert-ProtectedDirectory $parent $false $true
  # A shared parent may allow creation of new children, but never replacement of protected children.
  # Create the child with its final DACL in the kernel; never create then repair an inherited leaf.
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $descriptor = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
  if (-not $PrivateLeaf) { $descriptor += '(A;OICI;0x1200a9;;;BU)' }
  $acl.SetSecurityDescriptorSddlForm($descriptor)
  if ($PSVersionTable.PSEdition -eq 'Desktop') { [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null }
  else { [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path),$acl) }
  Assert-ProtectedDirectory $Path $PrivateLeaf
}
function Assert-ProtectedFile([string]$Path) {
  $file = Get-Item -LiteralPath $Path -Force
  if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Trusted file cannot be a directory or reparse point.' }
  $acl = Get-Acl -LiteralPath $Path
  if ($null -eq ([Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)).DiscretionaryAcl) { throw 'Trusted file has an unrestricted DACL.' }
  $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Untrusted file owner.' }
  foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trusted) { continue }
    if (([long]$rule.FileSystemRights -band 0x500D0156) -ne 0) { throw 'Untrusted write access to release file.' }
  }
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated as IT administrator.' }
if (Get-Service -Name OneControlAgent -ErrorAction SilentlyContinue) { throw 'Service already exists. Use an approved signed release update.' }
$releaseRoot = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
# Runtime configuration and dependency maps must also come from an administrator-controlled release.
Assert-ProtectedDirectory $releaseRoot
foreach ($entry in (Get-ChildItem -LiteralPath $releaseRoot -Recurse -Force)) {
  if ($entry.PSIsContainer) { Assert-ProtectedDirectory $entry.FullName }
  else { Assert-ProtectedFile $entry.FullName }
}
Assert-ProtectedDirectory (Split-Path -Parent ([IO.Path]::GetFullPath($ReleasePublicKeyFile)))
Assert-ProtectedFile $ReleasePublicKeyFile
$installRoot = Join-Path $env:ProgramFiles 'OneControl\Agent'
$stateRoot = Join-Path $env:ProgramData 'OneControl\Agent'
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $stateRoot)) { throw 'Existing state found. IT must reconcile it before installation.' }
$installParent = Split-Path -Parent $installRoot
$stateParent = Split-Path -Parent $stateRoot
# Validate ancestors without changing shared OneControl/EMA permissions. Only replacement authority matters on shared parents.
foreach ($parent in @($installParent,$stateParent)) {
  if (-not (Test-Path -LiteralPath $parent)) { New-ProtectedDirectory $parent }
  Assert-ProtectedDirectory $parent $false $true
}
New-ProtectedDirectory $installRoot
New-ProtectedDirectory $stateRoot $true
# Copy first, then verify the protected bytes that will actually execute.
foreach ($module in @('Service','Broker','Provision','Recovery')) {
  $source = Join-Path $releaseRoot $module
  if ((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Release module cannot be a reparse point.' }
  foreach ($entry in (Get-ChildItem -LiteralPath $source -Recurse -Force)) {
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Release cannot contain reparse points.' }
  }
  Copy-Item -LiteralPath $source -Destination $installRoot -Recurse
}
Assert-ProtectedDirectory $installRoot
Assert-ProtectedDirectory $stateRoot $true
foreach ($directory in (Get-ChildItem -LiteralPath $installRoot -Recurse -Directory)) { Assert-ProtectedDirectory $directory.FullName }
foreach ($file in (Get-ChildItem -LiteralPath $installRoot -Recurse -File -Force)) { Assert-ProtectedFile $file.FullName }
$binaryPaths = @('Service\OneControl.Agent.Service.exe','Broker\OneControl.Agent.Broker.exe','Provision\OneControl.Agent.Provision.exe','Recovery\OneControl.Agent.Recovery.exe')
foreach ($relative in $binaryPaths) {
  $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $installRoot $relative)
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint) { throw "Untrusted binary: $relative" }
}
# Every executable module must be signed by the selected publisher. Unmanaged DLLs also require trust.
$trustedPublishers = @($PublisherThumbprint) + $DependencyPublisherThumbprints
foreach ($binary in (Get-ChildItem -LiteralPath $installRoot -Recurse -File | Where-Object Extension -In '.exe','.dll')) {
  if ($binary.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installed module cannot be a reparse point.' }
  $signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -notin $trustedPublishers) {
    throw "Unsigned dependency or unapproved publisher: $($binary.Name)"
  }
}
# No inherited access for ordinary users. Admins can inspect files; privileged admins can always take ownership.
& icacls.exe $stateRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot secure state directory' }
& icacls.exe $installRoot '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot secure binary directory' }
Copy-Item -LiteralPath $ReleasePublicKeyFile -Destination (Join-Path $installRoot 'release-public.pem')
$enrollment = Get-Content -Raw -LiteralPath $EnrollmentFile | ConvertFrom-Json
$enrollment.brokerPath = Join-Path $installRoot 'Broker\OneControl.Agent.Broker.exe'
$enrollment.releasePublicKeyFile = Join-Path $installRoot 'release-public.pem'
$provisionInput = Join-Path $stateRoot 'enrollment.json'
# The elevated provisioner needs temporary write access; remove it after successful enrollment.
& icacls.exe $stateRoot '/grant:r' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot enable provisioning access' }
try {
  $enrollment | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $provisionInput
  & (Join-Path $installRoot 'Provision\OneControl.Agent.Provision.exe') $provisionInput (Join-Path $stateRoot 'agent.json')
  if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed; reconcile preserved installation state before retrying.' }
} finally {
  if (Test-Path -LiteralPath $provisionInput) { Remove-Item -LiteralPath $provisionInput }
  & icacls.exe $stateRoot '/grant:r' '*S-1-5-32-544:(OI)(CI)RX' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot restore protected state access' }
}
New-Service -Name 'OneControlAgent' -BinaryPathName ('"' + (Join-Path $installRoot 'Service\OneControl.Agent.Service.exe') + '"') `
  -DisplayName 'One Control Agent' -Description 'Managed device inventory and approved update orchestration' -StartupType Automatic | Out-Null
New-Service -Name 'OneControlRecovery' -BinaryPathName ('"' + (Join-Path $installRoot 'Recovery\OneControl.Agent.Recovery.exe') + '"') `
  -DisplayName 'One Control Recovery' -Description 'Independent signed agent update and recovery watchdog' -StartupType Automatic | Out-Null
& sc.exe failure OneControlAgent reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service recovery' }
& sc.exe failure OneControlRecovery reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure independent recovery' }
Start-Service -Name 'OneControlRecovery'
Start-Service -Name 'OneControlAgent'
Write-Output 'SYSTEM service installed. The optional IT console is separate and was not installed.'
