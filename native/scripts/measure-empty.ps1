param(
    [Parameter(Mandatory = $true)][string] $Binary,
    [Parameter(Mandatory = $true)][string] $EvidenceRoot
)
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$evidencePath = (Resolve-Path -LiteralPath $EvidenceRoot).Path
$workPath = Join-Path ([IO.Path]::GetTempPath()) ('onecontrol-empty-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workPath | Out-Null
$stdout = Join-Path $evidencePath 'empty-stdout.json'
$stderr = Join-Path $evidencePath 'empty-stderr.txt'
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $binaryPath
$startInfo.Arguments = '--observe-for=20s'
$startInfo.WorkingDirectory = $workPath
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$process = [Diagnostics.Process]::new()
$process.StartInfo = $startInfo
if (-not $process.Start()) { throw 'The empty-selection process did not start.' }
$stdoutRead = $process.StandardOutput.ReadToEndAsync()
$stderrRead = $process.StandardError.ReadToEndAsync()
try {
    $samples = @()
    for ($index = 0; $index -lt 3; $index++) {
        if ($process.HasExited) { throw 'The observation process exited before all snapshots.' }
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)")
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $process.Id })
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $process.Id })
        $files = @(Get-ChildItem -LiteralPath $workPath -Recurse -Force)
        $samples += [pscustomobject]@{
            atUtc = [DateTime]::UtcNow.ToString('o')
            childProcesses = @($children | Select-Object ProcessId, Name)
            tcpEndpoints = @($tcp | Select-Object LocalAddress, LocalPort, State)
            udpEndpoints = @($udp | Select-Object LocalAddress, LocalPort)
            workingDirectoryEntries = $files.Count
        }
        if ($children.Count -ne 0 -or $tcp.Count -ne 0 -or $udp.Count -ne 0 -or $files.Count -ne 0) {
            $samples | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidencePath 'empty-observation-failure.json') -Encoding utf8
            throw 'The empty-selection process created a child, network endpoint or working directory file.'
        }
    }
    $process.WaitForExit()
    [IO.File]::WriteAllText($stdout, $stdoutRead.GetAwaiter().GetResult())
    [IO.File]::WriteAllText($stderr, $stderrRead.GetAwaiter().GetResult())
    if ($process.ExitCode -ne 0) { throw "Bootstrap exited with $($process.ExitCode)." }
    $result = [pscustomobject]@{
        binary = $binaryPath
        binaryBytes = (Get-Item -LiteralPath $binaryPath).Length
        sha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        processId = $process.Id
        exitCode = $process.ExitCode
        workingDirectory = $workPath
        samples = $samples
        finalWorkingDirectoryEntries = @(Get-ChildItem -LiteralPath $workPath -Recurse -Force).Count
        observationLimit = 'Three live OS snapshots during a 20-second idle run. This does not measure transient lifetime events or the 30-minute idle acceptance budget.'
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidencePath 'empty-observation.json') -Encoding utf8
    $result | ConvertTo-Json -Depth 8
} finally {
    if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $process.Dispose()
}
