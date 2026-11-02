param(
    [Parameter(Mandatory=$true)][string]$RunDirectory,
    [string]$Attack = 'asb_concat',
    [string]$Suite = 'slack',
    [string]$BenchmarkVersion = 'v1',
    [string]$UserTasks = 'user_task_0',
    [string]$InjectionTasks = 'injection_task_4'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskApiPointer = [IntPtr]::Zero
try {
    $taskAlias = (Get-Content -LiteralPath (Join-Path $taskRoot 'configs/pilot.json') -Raw | ConvertFrom-Json).gateway_key_name
    if ($taskAlias -ne 'deepseek-dev') { throw 'No key fallback allowed' }
    $taskSecret = ConvertTo-SecureString ((Get-Content -LiteralPath (Join-Path $taskRoot 'DataSet/.private/deepseek-dev.dpapi') -Raw).Trim())
    $taskApiPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecret)
    $env:LOGBENCH_GATEWAY_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskApiPointer)
    & 'C:/Users/WXQ/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe' -X utf8 (Join-Path $PSScriptRoot 'agentdojo_official_ten.py') `
        --run-dir $RunDirectory --attack $Attack --suite $Suite --benchmark-version $BenchmarkVersion `
        --user-tasks $UserTasks --injection-tasks $InjectionTasks
    $taskExit = $LASTEXITCODE
} finally {
    if ($taskApiPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskApiPointer) }
    Remove-Item Env:LOGBENCH_GATEWAY_KEY -ErrorAction SilentlyContinue
}
exit $taskExit
