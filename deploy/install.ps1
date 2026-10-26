param(
    [string]$BundleDirectory = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonLauncher = 'py'
)

$ErrorActionPreference = 'Stop'

$installer = Join-Path $PSScriptRoot 'installer.py'
& $PythonLauncher -3 -c 'import sys; assert sys.version_info >= (3, 11), "LeakGuard requires Python 3.11 or newer"'
if ($LASTEXITCODE -ne 0) {
    throw 'Python 3.11 or newer is required. Install a per-user Python runtime and retry.'
}
& $PythonLauncher -3 $installer install $BundleDirectory
if ($LASTEXITCODE -ne 0) {
    throw 'LeakGuard installation failed; existing active release was left in place.'
}
Write-Host 'LeakGuard is installed for this user. Use LeakGuard Doctor and LeakGuard Manage in the Start Menu, or run the per-user leakguard-install.cmd from LOCALAPPDATA.'
