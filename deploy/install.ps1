param(
    [string]$BundleDirectory = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonLauncher = 'py'
)

$ErrorActionPreference = 'Stop'

$installer = Join-Path $PSScriptRoot 'installer.py'
$manifestPath = Join-Path $BundleDirectory 'release.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'The extracted bundle is missing release.json.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$targetPython = [string]$manifest.target_python
if ($targetPython -notmatch '^3\.[0-9]{1,2}$') {
    throw 'The bundle has no valid target Python version.'
}
$pythonSelector = "-$targetPython"
& $PythonLauncher $pythonSelector -c "import sys; assert f'{sys.version_info.major}.{sys.version_info.minor}' == '$targetPython', 'Bundle requires Python $targetPython'"
if ($LASTEXITCODE -ne 0) {
    throw "Python $targetPython is required. Install a per-user matching runtime, then retry."
}
& $PythonLauncher $pythonSelector $installer install $BundleDirectory
if ($LASTEXITCODE -ne 0) {
    throw 'LeakGuard installation failed; existing active release was left in place.'
}
Write-Host 'LeakGuard is installed for this user. Use LeakGuard Doctor and LeakGuard Manage in the Start Menu, or run the per-user leakguard-install.cmd from LOCALAPPDATA.'
