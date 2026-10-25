param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$PythonPath = 'python',
    [Parameter(Mandatory=$true)][string]$StateDirectory
)
$ErrorActionPreference = 'Stop'
$env:LEAKGUARD_CONFIG = [IO.Path]::GetFullPath($ConfigPath)
$env:LEAKGUARD_STATE_DIR = [IO.Path]::GetFullPath($StateDirectory)
$scannerPython = (Get-Command $PythonPath -ErrorAction Stop).Source
$scannerState = $env:LEAKGUARD_STATE_DIR
New-Item -ItemType Directory -Path $scannerState -Force | Out-Null
$scannerConfig = Get-Content -LiteralPath $env:LEAKGUARD_CONFIG -Raw | ConvertFrom-Json
$scannerConfig.exclude_roots = @($scannerConfig.exclude_roots) + $scannerState
$shareNames = @($scannerConfig.profiles.general.sources)
$shareBudget = [Math]::Max(30, [Math]::Floor(900 / [Math]::Max(1,$shareNames.Count)))
foreach ($shareName in $shareNames) {
    & $scannerPython -X utf8 -m leakguard_core audit $shareName --budget-seconds $shareBudget --max-files 10000
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$companionNames = @($scannerConfig.profiles.companion.sources)
$companionBudget = [Math]::Max(15, [Math]::Floor(60 / [Math]::Max(1,$companionNames.Count)))
foreach ($companionName in $companionNames) {
    & $scannerPython -X utf8 -m leakguard_core audit $companionName --budget-seconds $companionBudget --max-files 1000
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
exit $LASTEXITCODE
