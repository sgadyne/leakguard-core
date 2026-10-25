param(
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [Parameter(Mandatory=$true)][string]$StateDirectory
)
$ErrorActionPreference = 'Stop'
$configFile = (Resolve-Path -LiteralPath $ConfigPath).Path
$pythonFile = (Get-Command $PythonPath -ErrorAction Stop).Source
$stateFolder = [IO.Path]::GetFullPath($StateDirectory)
New-Item -ItemType Directory -Path $stateFolder -Force | Out-Null
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $stateFolder /inheritance:r /grant:r "*${currentSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict runtime state permissions' }
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
$powerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
foreach ($name in @('Watch','Audit')) {
    $scriptFile = Join-Path $PSScriptRoot ($name + '.ps1')
    $arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -File "' + $scriptFile + '" -ConfigPath "' + $configFile + '" -PythonPath "' + $pythonFile + '" -StateDirectory "' + $stateFolder + '"'
    $action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments
    if ($name -eq 'Watch') { $trigger = New-ScheduledTaskTrigger -AtLogOn -User $principal.UserId }
    else { $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6) }
    Register-ScheduledTask -TaskName ('LeakGuard-Core-' + $name) -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
}
Write-Output 'Registered optional per-user tasks. Start LeakGuard-Core-Watch explicitly when ready.'
