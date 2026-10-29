[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ReleaseDirectory,
  [Parameter(Mandatory)][ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version,
  [Parameter(Mandatory)][string]$OutputFile,
  [string]$Wix = 'wix'
)
$ErrorActionPreference = 'Stop'
$release = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$output = [IO.Path]::GetFullPath($OutputFile)
if ([IO.Path]::GetExtension($output) -ne '.msi' -or (Test-Path -LiteralPath $output)) { throw 'Select a new MSI output file.' }
$versionNumber = [version]$Version
if ($versionNumber.Major -gt 255 -or $versionNumber.Minor -gt 255 -or $versionNumber.Build -gt 65535) { throw 'Version exceeds Windows Installer limits.' }
$source = [IO.Path]::ChangeExtension($output,'.wxs')
if (Test-Path -LiteralPath $source) { throw 'Packaging source already exists; choose a fresh output.' }
$namespace = 'http://wixtoolset.org/schemas/v4/wxs'
$document = [xml]::new()
function Add-Element([Xml.XmlElement]$Parent,[string]$Name,[hashtable]$Attributes) {
  $element = $document.CreateElement($Name,$namespace)
  foreach ($key in $Attributes.Keys) { $element.SetAttribute($key,[string]$Attributes[$key]) }
  if ($null -eq $Parent) { [void]$document.AppendChild($element) } else { [void]$Parent.AppendChild($element) }
  return $element
}
$root = Add-Element $null 'Wix' @{}
$package = Add-Element $root 'Package' @{Name=('One Control Agent Payload '+$Version);Manufacturer='OneControl';Version=$Version;UpgradeCode='3C927D05-67EC-44A8-A1EF-7B674D81EA51';Scope='perMachine'}
[void](Add-Element $package 'MediaTemplate' @{EmbedCab='yes'})
[void](Add-Element $package 'Property' @{Id='ONE_CONTROL_PAYLOAD_KIND';Value='stage_only'})
[void](Add-Element $package 'Property' @{Id='ONE_CONTROL_PAYLOAD_VERSION';Value=$Version})
$programFiles = Add-Element $package 'StandardDirectory' @{Id='ProgramFiles64Folder'}
$vendor = Add-Element $programFiles 'Directory' @{Id='Vendor';Name='OneControl'}
$product = Add-Element $vendor 'Directory' @{Id='Product';Name='Agent'}
$versions = Add-Element $product 'Directory' @{Id='Versions';Name='versions'}
$destination = Add-Element $versions 'Directory' @{Id='Payload';Name=$Version}
$feature = Add-Element $package 'Feature' @{Id='Main';Title='Immutable versioned agent payload';Level='1'}
$index = 0
foreach ($module in @('Service','Broker','Provision')) {
  $modulePath = Join-Path $release $module
  $executable = Join-Path $modulePath ('OneControl.Agent.'+$module+'.exe')
  if (-not (Test-Path -LiteralPath $executable)) { throw ('Missing single-file module: '+$module) }
  $entries = @(Get-ChildItem -LiteralPath $modulePath -Recurse -File -Force | Where-Object Extension -NotIn '.pdb')
  # The supported package layout is deliberately flat and self-contained.
  if (@(Get-ChildItem -LiteralPath $modulePath -Directory -Force).Count -ne 0) { throw 'Publish single-file modules before packaging.' }
  $directory = Add-Element $destination 'Directory' @{Id=('Module'+$module);Name=$module}
  foreach ($file in $entries) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Payload cannot contain reparse points.' }
    if ($file.Extension -in '.exe','.dll') {
      $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
      if ($signature.Status -ne 'Valid') { throw ('Payload binary is not trusted: '+$file.Name) }
      if ($file.Name -like 'OneControl.Agent.*' -and [version]$file.VersionInfo.FileVersion -ne [version]($Version+'.0')) { throw 'Payload binary version does not match the package.' }
    }
    $index++
    $component = Add-Element $directory 'Component' @{Id=('C'+$index);Guid='*'}
    [void](Add-Element $component 'File' @{Id=('F'+$index);Source=$file.FullName;KeyPath='yes'})
    [void](Add-Element $feature 'ComponentRef' @{Id=('C'+$index)})
  }
}
$document.Save($source)
& $Wix build $source -arch x64 -pdbtype none -o $output
if ($LASTEXITCODE -ne 0) { throw 'Agent payload MSI build failed.' }
Write-Output 'Versioned payload MSI created. Sign it before release; it does not install or change a service.'
