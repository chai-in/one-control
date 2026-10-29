$ErrorActionPreference = 'Stop'
$failures = @()
foreach ($script in (Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File -Recurse)) {
  $tokens = $null; $parseErrors = $null
  [Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
  if ($parseErrors.Count -gt 0) { $failures += $parseErrors }
}
if ($failures.Count -gt 0) { $failures | ForEach-Object { Write-Error $_.Message }; exit 1 }
Write-Output 'PowerShell scripts parse successfully.'
