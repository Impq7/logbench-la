param(
    [Parameter(Mandatory=$true)][string]$PlanPath,
    [Parameter(Mandatory=$true)][string]$BatchId,
    [int]$Start = 1,
    [int]$Count = 80
)
# Serial collector for a frozen official-engine plan (legacy filename).
# Decrypts the gateway key once (DPAPI), then loops the plan.json entries through
# agentdojo_official_ten.py. Serial (one isolated container per session).
# Each session is packed into DataSet immediately after collection (边采集边打包):
# Raw evidence is copied and hash-checked; the original run directory is retained.
$ErrorActionPreference = 'Stop'
$root = 'D:\download\workbuddy\LogBench-LA'
$planPath = (Resolve-Path -LiteralPath $PlanPath).Path
$py = 'C:/Users/WXQ/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$packScript = Join-Path $root 'scripts\pack_official_batch.py'

$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
$samples = @($plan.samples)
$end = [Math]::Min($Start + $Count - 1, $samples.Count)
& $py -B $packScript --plan $planPath --batch-id $BatchId --freeze-only
if ($LASTEXITCODE -ne 0) { throw 'Batch freeze failed' }
$journal = Join-Path (Split-Path $planPath -Parent) 'attempts.jsonl'

$ptr = [IntPtr]::Zero
try {
    $secret = ConvertTo-SecureString ((Get-Content -LiteralPath (Join-Path $root 'DataSet\.private\deepseek-dev.dpapi') -Raw).Trim())
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    $env:LOGBENCH_GATEWAY_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)

    foreach ($s in $samples) {
        if ($s.seq -lt $Start -or $s.seq -gt $end) { continue }
        $runDir = Join-Path $root ("experiment\" + $s.run_dir)
        $pyArgs = @('-X', 'utf8', (Join-Path $root 'scripts\agentdojo_official_ten.py'),
                     '--run-dir', $runDir, '--attack', $s.attack,
                     '--suite', $plan.scenario,
                     '--user-tasks', $s.user_task)
        if ($plan.model_id) { $pyArgs += @('--model-id', $plan.model_id) }
        if ($plan.reasoning_effort) { $pyArgs += @('--reasoning-effort', $plan.reasoning_effort) }
        if ($s.injection_task) {
            $pyArgs += @('--injection-tasks', $s.injection_task)
        }
        Write-Output "=== [$($s.seq)/$($samples.Count)] $($s.user_task) / $($s.attack) -> $($s.run_dir)"
        & $py @pyArgs
        @{seq=$s.seq; stage='collect'; exit_code=$LASTEXITCODE; run_dir=$s.run_dir} | ConvertTo-Json -Compress | Add-Content -LiteralPath $journal -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            throw "Collection failed at seq=$($s.seq); batch stopped"
        }
        # Publish only after collection QA; retain the original evidence.
        & $py -X utf8 $packScript $runDir --plan $planPath --batch-id $BatchId
        @{seq=$s.seq; stage='pack'; exit_code=$LASTEXITCODE; run_dir=$s.run_dir} | ConvertTo-Json -Compress | Add-Content -LiteralPath $journal -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            throw "Packing failed at seq=$($s.seq); batch stopped"
        }
        $sessionId = (Get-Content -LiteralPath (Join-Path $runDir 'report.json') -Raw | ConvertFrom-Json).run_id
        $published = Join-Path $root "DataSet/$BatchId/$($plan.scenario)/sessions/$sessionId/model_inputs/T.atif.json"
        if (-not (Test-Path -LiteralPath $published)) { throw "Packing produced no session at seq=$($s.seq)" }
    }
    Write-Output "DONE range $Start..$end"
} finally {
    if ($ptr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    Remove-Item Env:LOGBENCH_GATEWAY_KEY -ErrorAction SilentlyContinue
}
