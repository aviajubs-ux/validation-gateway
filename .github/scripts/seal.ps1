[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$runRoot = Join-Path $env:RUNNER_TEMP 'validation'
$evidenceRoot = Join-Path $runRoot 'evidence'
$plainArchive = Join-Path $env:RUNNER_TEMP 'evidence-plaintext.zip'
$sealDirectory = Join-Path $env:GITHUB_WORKSPACE 'sealed'
$sealedFile = Join-Path $sealDirectory 'evidence.bin'
$key=$null; $plaintext=$null; $ciphertext=$null; $stream=$null; $aes=$null
try {
    if ([string]::IsNullOrWhiteSpace($env:EVIDENCE_KEY_B64)) { throw 'EVIDENCE_KEY_MISSING' }
    $key=[Convert]::FromBase64String($env:EVIDENCE_KEY_B64)
    if($key.Length -ne 32){throw 'EVIDENCE_KEY_LENGTH_INVALID'}
    New-Item -ItemType Directory -Path $sealDirectory -Force | Out-Null
    if(!(Test-Path -LiteralPath $evidenceRoot)){
        New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $evidenceRoot 'execution-result.json'),'{"status":"NO_EVIDENCE_DIRECTORY"}',[Text.UTF8Encoding]::new($false))
    }
    if(Test-Path -LiteralPath $plainArchive){Remove-Item -LiteralPath $plainArchive -Force}
    Compress-Archive -Path (Join-Path $evidenceRoot '*') -DestinationPath $plainArchive -CompressionLevel Optimal -Force
    $nonce=[byte[]]::new(12); $tag=[byte[]]::new(16)
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try{$rng.GetBytes($nonce)}finally{$rng.Dispose()}
    $plaintext=[IO.File]::ReadAllBytes($plainArchive)
    $ciphertext=[byte[]]::new($plaintext.Length)
    $aad=[Text.Encoding]::UTF8.GetBytes('sealed-evidence-v1')
    $aes=[Security.Cryptography.AesGcm]::new($key,16)
    try {
        $aes.Encrypt($nonce,$plaintext,$ciphertext,$tag,$aad)
        $check=[byte[]]::new($plaintext.Length)
        $aes.Decrypt($nonce,$ciphertext,$tag,$check,$aad)
        for($i=0;$i -lt $plaintext.Length;$i++){if($plaintext[$i] -ne $check[$i]){throw 'ENCRYPTION_SELF_CHECK_FAILED'}}
        [Array]::Clear($check,0,$check.Length)
    } finally {$aes.Dispose();$aes=$null}
    $stream=[IO.MemoryStream]::new()
    $magic=[Text.Encoding]::ASCII.GetBytes('VGE1')
    $stream.Write($magic,0,$magic.Length); $stream.Write($nonce,0,$nonce.Length)
    $stream.Write($tag,0,$tag.Length); $stream.Write($ciphertext,0,$ciphertext.Length)
    [IO.File]::WriteAllBytes($sealedFile,$stream.ToArray())
    if(!(Test-Path -LiteralPath $sealedFile -PathType Leaf) -or (Get-Item $sealedFile).Length -lt 33){throw 'SEALED_ARTIFACT_INVALID'}
    Add-Content -LiteralPath $env:GITHUB_OUTPUT -Value 'sealed=true'
    Write-Output 'EVIDENCE_SEALED'
} finally {
    if($aes){$aes.Dispose()}
    if($stream){$stream.Dispose()}
    if($key){[Array]::Clear($key,0,$key.Length)}
    if($plaintext){[Array]::Clear($plaintext,0,$plaintext.Length)}
    if($ciphertext){[Array]::Clear($ciphertext,0,$ciphertext.Length)}
    if(Test-Path -LiteralPath $plainArchive){Remove-Item -LiteralPath $plainArchive -Force -ErrorAction SilentlyContinue}
    if(Test-Path -LiteralPath $runRoot){Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue}
}
