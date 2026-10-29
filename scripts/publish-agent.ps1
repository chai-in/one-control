[CmdletBinding()]
param(
  [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\.local\release'),
  [string]$Dotnet = 'dotnet',
  [ValidatePattern('^\d{1,5}\.\d{1,5}\.\d{1,5}$')][string]$Version = ([xml](Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\Directory.Build.props'))).Project.PropertyGroup.Version
)
$ErrorActionPreference = 'Stop'
$releaseRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $releaseRoot) { throw 'Output directory exists. Choose a new release directory.' }
New-Item -ItemType Directory -Path $releaseRoot | Out-Null
foreach ($module in @('Service', 'Broker', 'Provision', 'Recovery')) {
  $project = Join-Path $PSScriptRoot ("..\agent\OneControl.Agent.$module\OneControl.Agent.$module.csproj")
  & $Dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:RestoreLockedMode=true -p:Version=$Version -o (Join-Path $releaseRoot $module)
  if ($LASTEXITCODE -ne 0) { throw "Failed to publish $module" }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-agent.ps1') -Destination $releaseRoot
Get-ChildItem -LiteralPath $releaseRoot -Recurse -File | Get-FileHash -Algorithm SHA256 |
  Select-Object @{Name='Path';Expression={$_.Path.Substring($releaseRoot.Length + 1)}},Hash |
  ConvertTo-Json | Set-Content -LiteralPath (Join-Path $releaseRoot 'checksums.json')
Write-Output 'Published independent self-contained modules. Sign binaries and package an MSI before production distribution.'
