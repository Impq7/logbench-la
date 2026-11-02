$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskPointer = [IntPtr]::Zero
try {
    $taskSecure = ConvertTo-SecureString ((Get-Content -LiteralPath (Join-Path $taskRoot 'DataSet/.private/deepseek-dev.dpapi') -Raw).Trim())
    $taskPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecure)
    $env:LOGBENCH_DIAGNOSTIC_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer)
    & 'C:/Users/WXQ/.workbuddy/binaries/python/envs/default/Scripts/python.exe' -X utf8 (Join-Path $PSScriptRoot 'diagnose_completion_local.py')
    $taskExit = $LASTEXITCODE
} finally {
    if ($taskPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer) }
    Remove-Item Env:LOGBENCH_DIAGNOSTIC_KEY -ErrorAction SilentlyContinue
}
exit $taskExit
