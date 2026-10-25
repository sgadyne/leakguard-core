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
$pendingChanges = [Collections.Concurrent.ConcurrentQueue[object]]::new()
$pendingErrors = [Collections.Concurrent.ConcurrentQueue[object]]::new()
$eventContext = @{ Queue=$pendingChanges; Errors=$pendingErrors; Roots=@($scannerConfig.exclude_roots); ComponentPattern=('(?i)[\\/](' + (($scannerConfig.exclude_components | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')[\\/]'); Overflow=$false }
$watchScopes = $scannerConfig.watch_scopes
if (-not $watchScopes) { $watchScopes = $scannerConfig.audit_scopes }
$recentErrors = [Collections.Generic.List[object]]::new()
$watchers = @{}
$subscriptions = @{}
$queueDirectory = Join-Path $scannerState 'queue'
New-Item -ItemType Directory -Path $queueDirectory -Force | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
$lastFlush = [DateTime]::UtcNow
$lastStatus = [DateTime]::MinValue
$drainProcess = $null

function Test-ExcludedPath([string]$filePath) {
    foreach ($excludedRoot in $scannerConfig.exclude_roots) {
        $prefix = $excludedRoot.Replace('/','\').TrimEnd('\')
        if ($filePath.Equals($prefix,[StringComparison]::OrdinalIgnoreCase) -or $filePath.StartsWith($prefix + '\',[StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($component in $scannerConfig.exclude_components) {
        if ($filePath -match ('(?i)[\\/]' + [regex]::Escape($component) + '[\\/]')) { return $true }
    }
    return $false
}

try {
    while ($true) {
        if ($drainProcess -and $drainProcess.HasExited) {
            if ($drainProcess.ExitCode -ne 0) { $pendingErrors.Enqueue(@{ scope='queue'; root=$queueDirectory; type=('DrainExit' + $drainProcess.ExitCode); observed=[DateTime]::UtcNow.ToString('o') }) }
            $drainProcess.Dispose(); $drainProcess=$null
        }
        foreach ($scopeProperty in $watchScopes.PSObject.Properties) {
            $scopeName = $scopeProperty.Name
            $scopeRoot = [string]$scopeProperty.Value
            if (-not $watchers.ContainsKey($scopeName) -and (Test-Path -LiteralPath $scopeRoot -PathType Container)) {
                try {
                    $watcher = [IO.FileSystemWatcher]::new($scopeRoot)
                    $watcher.IncludeSubdirectories = $true
                    $watcher.InternalBufferSize = 32768
                    $watcher.NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite, DirectoryName'
                    $rootContext = $eventContext.Clone()
                    $rootContext.Scope = $scopeName
                    $rootContext.Root = $scopeRoot
                    foreach ($eventName in @('Created','Changed','Renamed','Deleted')) {
                        $subscription = Register-ObjectEvent -InputObject $watcher -EventName $eventName -MessageData $rootContext -Action {
                            $context = $event.MessageData
                            $eventArgs = $event.SourceEventArgs
                            $fullPath = $eventArgs.FullPath
                            $skip = $fullPath -match $context.ComponentPattern
                            foreach ($excludedRoot in $context.Roots) {
                                $prefix = $excludedRoot.Replace('/','\').TrimEnd('\')
                                if ($fullPath.StartsWith($prefix + '\',[StringComparison]::OrdinalIgnoreCase)) { $skip=$true; break }
                            }
                            if (-not $skip) {
                                if ($context.Queue.Count -lt 20000) {
                                    $record = @{ path=$fullPath; kind=$eventArgs.ChangeType.ToString().ToLowerInvariant(); observed=[DateTime]::UtcNow.ToString('o') }
                                    if ($eventArgs -is [IO.RenamedEventArgs]) { $record.old_path=$eventArgs.OldFullPath }
                                    $context.Queue.Enqueue($record)
                                } elseif (-not $context.Overflow) { $context.Errors.Enqueue(@{ scope=$context.Scope; root=$context.Root; type='QueueCapacity'; observed=[DateTime]::UtcNow.ToString('o') }); $context.Overflow=$true }
                            }
                        }
                        $subscriptions[$scopeName + '-' + $eventName] = $subscription
                    }
                    $subscriptions[$scopeName + '-Error'] = Register-ObjectEvent -InputObject $watcher -EventName Error -MessageData $rootContext -Action { $context=$event.MessageData; $context.Errors.Enqueue(@{ scope=$context.Scope; root=$context.Root; type=$event.SourceEventArgs.GetException().GetType().Name; observed=[DateTime]::UtcNow.ToString('o') }) }
                    $watcher.EnableRaisingEvents = $true
                    $watchers[$scopeName] = $watcher
                } catch {
                    [IO.File]::WriteAllText((Join-Path $scannerState ('watch-' + $scopeName + '-error.txt')),([DateTime]::UtcNow.ToString('o') + ' ' + $_.Exception.GetType().Name),$utf8)
                }
            }
        }
        $errorRecord = $null
        while ($pendingErrors.TryDequeue([ref]$errorRecord)) {
            $recentErrors.Add($errorRecord)
            if ($recentErrors.Count -gt 100) { $recentErrors.RemoveAt(0) }
            [IO.File]::WriteAllText((Join-Path $scannerState 'watch-reconciliation-needed.txt'),($errorRecord | ConvertTo-Json -Compress),$utf8)
            if ($errorRecord.type -notin @('InternalBufferOverflowException','QueueCapacity') -and $watchers.ContainsKey($errorRecord.scope)) {
                $watchers[$errorRecord.scope].Dispose(); $watchers.Remove($errorRecord.scope)
                foreach ($eventName in @('Created','Changed','Renamed','Deleted','Error')) {
                    $key = $errorRecord.scope + '-' + $eventName
                    if ($subscriptions.ContainsKey($key)) {
                        Unregister-Event -SubscriptionId $subscriptions[$key].Id -ErrorAction SilentlyContinue
                        Remove-Job -Id $subscriptions[$key].Id -Force -ErrorAction SilentlyContinue
                        $subscriptions.Remove($key)
                    }
                }
            }
        }
        if (([DateTime]::UtcNow - $lastFlush).TotalSeconds -ge 60) {
            $batch = [Collections.Generic.List[object]]::new()
            $changedRecord = $null
            while ($pendingChanges.TryDequeue([ref]$changedRecord)) { if (-not (Test-ExcludedPath $changedRecord.path)) { $batch.Add($changedRecord) } }
            if ($batch.Count -gt 0) {
                $queuePath = Join-Path $queueDirectory ([Guid]::NewGuid().ToString('N') + '.json')
                $json = ConvertTo-Json -InputObject @($batch.ToArray()) -Depth 5 -Compress
                [IO.File]::WriteAllText($queuePath,$json,$utf8)
            }
            # Keep event delivery/status responsive while the single content worker runs.
            # Both streams are consumed and discarded; reports already contain safe metadata.
            if (-not $drainProcess) {
                $startInfo = [Diagnostics.ProcessStartInfo]::new()
                $startInfo.FileName = $scannerPython
                $startInfo.Arguments = '-X utf8 -m leakguard_core drain'
                $startInfo.UseShellExecute = $false
                $startInfo.CreateNoWindow = $true
                $startInfo.RedirectStandardOutput = $true
                $startInfo.RedirectStandardError = $true
                $drainProcess = [Diagnostics.Process]::new()
                $drainProcess.StartInfo = $startInfo
                [void]$drainProcess.Start()
                $drainProcess.BeginOutputReadLine()
                $drainProcess.BeginErrorReadLine()
            }
            $lastFlush = [DateTime]::UtcNow
        }
        if (([DateTime]::UtcNow - $lastStatus).TotalSeconds -ge 30) {
            $status = @{ updated_utc=[DateTime]::UtcNow.ToString('o'); process_id=$PID; watching=@($watchers.Keys); configured_roots=@($watchScopes.PSObject.Properties.Name); queued_paths=$pendingChanges.Count; content_worker_running=($null -ne $drainProcess); profiles=@('general','companion'); scope='this workstation only'; reconciliation_needed=(Test-Path -LiteralPath (Join-Path $scannerState 'watch-reconciliation-needed.txt')); recent_errors=@($recentErrors.ToArray()) }
            [IO.File]::WriteAllText((Join-Path $scannerState 'watch-status.json'),($status | ConvertTo-Json -Depth 4),$utf8)
            $lastStatus = [DateTime]::UtcNow
        }
        Start-Sleep -Seconds 2
    }
} finally {
    foreach ($watcher in $watchers.Values) { $watcher.Dispose() }
    foreach ($subscription in $subscriptions.Values) { Unregister-Event -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue }
}
