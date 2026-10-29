# Shared local administration storage. Does not read, generate or print credentials.
$script:PrivateStorageTrustedOwners = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Assert-PrivateStoragePath {
  param([Parameter(Mandatory)][string]$Path,[switch]$Directory,[switch]$ParentOnly)
  $absolute = [IO.Path]::GetFullPath($Path)
  if ($absolute.StartsWith('\\')) { throw 'Administration requires local protected storage.' }
  $entry = Get-Item -LiteralPath $absolute -Force
  if ($entry.PSIsContainer -ne [bool]$Directory) { throw 'Unexpected private storage path type.' }
  $leaf = -not $ParentOnly
  while ($null -ne $entry) {
    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Private storage cannot traverse reparse points.' }
    $acl = Get-Acl -LiteralPath $entry.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $script:PrivateStorageTrustedOwners -or
        $null -eq ([Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)).DiscretionaryAcl) { throw 'Private storage ownership or DACL is untrusted.' }
    $forbidden = $(if ($leaf) { 0x1f01ffL -bor 0xf0000000L } else { 0x000d0040L -bor 0x50000000L })
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
          $rule.IdentityReference.Value -notin $script:PrivateStorageTrustedOwners -and (([long]$rule.FileSystemRights -band $forbidden) -ne 0)) { throw 'Untrusted access to private administration storage.' }
    }
    $entry = $(if ($entry.PSIsContainer) { $entry.Parent } else { $entry.Directory })
    $leaf = $false
  }
}
function New-PrivateStorageDirectory([string]$Path) {
  Assert-PrivateStoragePath -Path (Split-Path -Parent $Path) -Directory -ParentOnly
  if (Test-Path -LiteralPath $Path) { throw 'Private storage target already exists; preserve it.' }
  $security = [Security.AccessControl.DirectorySecurity]::new()
  $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path),$security) | Out-Null
  Assert-PrivateStoragePath -Path $Path -Directory
}
function Write-PrivateStorageFile([string]$Path,[string]$Content) {
  Assert-PrivateStoragePath -Path (Split-Path -Parent $Path) -Directory
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
  $stream = [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
  try { $stream.Write($bytes); $stream.Flush($true) } finally { $stream.Dispose() }
  Assert-PrivateStoragePath -Path $Path
}
