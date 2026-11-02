param(
    [Parameter(Mandatory=$true)][ValidateSet('prepare','import','prompt')][string]$Mode,
    [string]$Ciphertext,
    [ValidateSet('wxq2','deepseek-dev')][string]$KeyName = 'wxq2'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$privateRoot = Join-Path $projectRoot 'DataSet/.private'
New-Item -ItemType Directory -Path $privateRoot -Force | Out-Null
$transportPath = Join-Path $privateRoot 'gateway-import-rsa.dpapi'
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
$rsa.PersistKeyInCsp = $false
$secretPointer = [IntPtr]::Zero
try {
    if ($Mode -eq 'prepare') {
        $privateXml = $rsa.ToXmlString($true)
        $protected = ConvertTo-SecureString $privateXml -AsPlainText -Force | ConvertFrom-SecureString
        [IO.File]::WriteAllText($transportPath, $protected)
        $parameters = $rsa.ExportParameters($false)
        $modulus = [Convert]::ToBase64String($parameters.Modulus).TrimEnd('=').Replace('+','-').Replace('/','_')
        $exponent = [Convert]::ToBase64String($parameters.Exponent).TrimEnd('=').Replace('+','-').Replace('/','_')
        @{ kty='RSA'; n=$modulus; e=$exponent } | ConvertTo-Json -Compress
    } elseif ($Mode -eq 'prompt') {
        $target = Join-Path $privateRoot ($KeyName + '.dpapi')
        if (Test-Path -LiteralPath $target) { throw 'Credential exists; refusing to overwrite' }
        $secureInput = Read-Host -Prompt 'Gateway credential (hidden)' -AsSecureString
        if ($secureInput.Length -lt 16) { throw 'Credential is too short' }
        $protected = ConvertFrom-SecureString $secureInput
        [IO.File]::WriteAllText($target, $protected)
        @{ imported=$true; key_name=$KeyName; storage='Windows DPAPI'; path=$target } | ConvertTo-Json -Compress
    } else {
        if (-not $Ciphertext) { throw 'Encrypted browser credential is required' }
        $secure = ConvertTo-SecureString ([IO.File]::ReadAllText($transportPath))
        $secretPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $rsa.FromXmlString([Runtime.InteropServices.Marshal]::PtrToStringBSTR($secretPointer))
        $bytes = $rsa.Decrypt([Convert]::FromBase64String($Ciphertext), $true)
        $plain = [Text.Encoding]::UTF8.GetString($bytes)
        if ($plain -notmatch '^sk-[A-Za-z0-9_-]+$') { throw 'Unexpected credential format' }
        $target = Join-Path $privateRoot ($KeyName + '.dpapi')
        if (Test-Path -LiteralPath $target) { throw 'Credential exists; refusing to overwrite' }
        $protected = ConvertTo-SecureString $plain -AsPlainText -Force | ConvertFrom-SecureString
        [IO.File]::WriteAllText($target, $protected)
        [Array]::Clear($bytes, 0, $bytes.Length)
        $plain = $null
        @{ imported=$true; key_name=$KeyName; storage='Windows DPAPI'; path=$target } | ConvertTo-Json -Compress
    }
} finally {
    if ($secretPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secretPointer) }
    $rsa.Dispose()
}
