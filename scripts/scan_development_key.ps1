$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$taskPointer = [IntPtr]::Zero
try {
    $taskSecure = ConvertTo-SecureString ((Get-Content -LiteralPath (Join-Path $taskRoot 'DataSet/.private/deepseek-dev.dpapi') -Raw).Trim())
    $taskPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecure)
    $taskSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer)
    $taskFiles = & rg --files experiment DataSet scripts configs -g '!DataSet/.private/**' -g '!DataSet/runtime-detectors/**' -g '!**/__pycache__/**'
    $taskMatches = @()
    $taskCount = 0
    foreach ($taskFile in $taskFiles) {
        $taskText = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes((Join-Path $taskRoot $taskFile)))
        if ($taskText.IndexOf($taskSecret, [StringComparison]::Ordinal) -ge 0) { $taskMatches += $taskFile }
        $taskCount++
    }
    $taskOutput = Join-Path $taskRoot ('experiment/credential-retention-audit-' + [guid]::NewGuid().ToString('N').Substring(0,12))
    [IO.Directory]::CreateDirectory($taskOutput) | Out-Null
    $taskReport = @{ kind='exact_current_key_retention_audit'; scanned_files=$taskCount; matching_files=$taskMatches; passed=($taskMatches.Count -eq 0); key_name='deepseek-dev'; timestamp_utc=[DateTime]::UtcNow.ToString('o') }
    $taskReport | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskOutput 'report.json') -Encoding UTF8
    @{output=$taskOutput; passed=$taskReport.passed; scanned_files=$taskCount; matches=$taskMatches.Count} | ConvertTo-Json
} finally {
    if ($taskPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer) }
    Remove-Variable taskSecret,taskText,taskSecure -ErrorAction SilentlyContinue
}
