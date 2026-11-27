[CmdletBinding()]
param(
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Read-ValidationWheelhouseManifest {
    param([Parameter(Mandatory=$true)][string]$ManifestPath)

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.schema -ne 'validation.python-wheelhouse.v1') { throw 'VALIDATION_DEPENDENCY_SCHEMA_INVALID' }
    if ($manifest.lock_file -notmatch '^[A-Za-z0-9_.-]+$') { throw 'VALIDATION_DEPENDENCY_LOCK_PATH_INVALID' }
    if ($manifest.lock_file_sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'VALIDATION_DEPENDENCY_LOCK_HASH_INVALID' }
    if ($null -eq $manifest.artifacts -or @($manifest.artifacts).Count -lt 1 -or @($manifest.artifacts).Count -gt 8) {
        throw 'VALIDATION_DEPENDENCY_ARTIFACT_COUNT_INVALID'
    }

    $manifestDirectory = Split-Path -Parent $ManifestPath
    $lockPath = Join-Path $manifestDirectory $manifest.lock_file
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw 'VALIDATION_DEPENDENCY_LOCK_MISSING' }
    $lockHash = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($lockHash -ne ([string]$manifest.lock_file_sha256).ToLowerInvariant()) {
        throw 'VALIDATION_DEPENDENCY_LOCK_HASH_MISMATCH'
    }

    $totalBytes = [int64]0
    $seenNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $validatedArtifacts = [System.Collections.Generic.List[object]]::new()
    foreach ($artifact in @($manifest.artifacts)) {
        if ([string]$artifact.filename -notmatch '^[A-Za-z0-9_.+-]+\.whl$') {
            throw 'VALIDATION_DEPENDENCY_WHEEL_FILENAME_INVALID'
        }
        if (-not $seenNames.Add([string]$artifact.filename)) { throw 'VALIDATION_DEPENDENCY_WHEEL_DUPLICATE' }
        if ([string]$artifact.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'VALIDATION_DEPENDENCY_WHEEL_HASH_INVALID'
        }
        $size = [int64]$artifact.size_bytes
        if ($size -lt 1 -or $size -gt 10000000) { throw 'VALIDATION_DEPENDENCY_WHEEL_SIZE_INVALID' }
        $totalBytes += $size
        if ($totalBytes -gt 25000000) { throw 'VALIDATION_DEPENDENCY_WHEELHOUSE_SIZE_LIMIT' }

        try { $uri = [Uri]([string]$artifact.url) }
        catch { throw 'VALIDATION_DEPENDENCY_WHEEL_URL_INVALID' }
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or
            $uri.DnsSafeHost -ne 'files.pythonhosted.org' -or
            $uri.Query -ne '' -or $uri.Fragment -ne '' -or
            $uri.AbsolutePath -notmatch '^/packages/[A-Za-z0-9._/-]+\.whl$') {
            throw 'VALIDATION_DEPENDENCY_WHEEL_URL_NOT_ALLOWLISTED'
        }
        $urlFileName = [Uri]::UnescapeDataString(($uri.AbsolutePath -split '/')[-1])
        if ($urlFileName -ne [string]$artifact.filename) { throw 'VALIDATION_DEPENDENCY_WHEEL_URL_NAME_MISMATCH' }

        $validatedArtifacts.Add([pscustomobject]@{
            FileName = [string]$artifact.filename
            Url = $uri.AbsoluteUri
            Sha256 = ([string]$artifact.sha256).ToLowerInvariant()
            SizeBytes = $size
        })
    }

    return [pscustomobject]@{
        ManifestDirectory = $manifestDirectory
        LockPath = $lockPath
        Artifacts = @($validatedArtifacts)
    }
}

function Select-ValidationPython {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        foreach ($minor in @('3.13','3.12')) {
            $selector = '-' + $minor
            & $launcher.Source $selector -c "import platform,sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == tuple(map(int, '$minor'.split('.'))) and sys.maxsize > 2**32 and platform.machine().lower() in ('amd64','x86_64') else 1)" 1>$null 2>$null
            if ($LASTEXITCODE -eq 0) {
                return [pscustomobject]@{ Executable=$launcher.Source; PrefixArgs=@($selector); Version=$minor }
            }
        }
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        & $python.Source -c "import platform,sys; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] in ((3,12),(3,13)) and sys.maxsize > 2**32 and platform.machine().lower() in ('amd64','x86_64') else 1)" 1>$null 2>$null
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{ Executable=$python.Source; PrefixArgs=@(); Version='selected' }
        }
    }
    throw 'VALIDATION_CPYTHON_312_OR_313_X64_REQUIRED'
}

function Initialize-ValidationDependencyWheelhouse {
    param(
        [Parameter(Mandatory=$true)][string]$CandidateRoot,
        [Parameter(Mandatory=$true)][string]$RunRoot
    )

    $excludedSegments = @('legacy_reference','archive','archives','backup','backups','obsolete','superseded','reference')
    $manifestCandidates = @(Get-ChildItem -LiteralPath $CandidateRoot -Filter 'validation-python-wheelhouse.json' -File -Recurse |
        Where-Object {
            $relative = [IO.Path]::GetRelativePath($CandidateRoot,$_.FullName)
            $segments = $relative -split '[\\/]'
            @($segments | Where-Object { $excludedSegments -contains $_ }).Count -eq 0
        })
    if ($manifestCandidates.Count -ne 1) { throw 'VALIDATION_DEPENDENCY_MANIFEST_LAYOUT_INVALID' }

    $validated = Read-ValidationWheelhouseManifest -ManifestPath $manifestCandidates[0].FullName
    $wheelhouse = Join-Path $RunRoot 'wheelhouse'
    $dependencyRoot = Join-Path $RunRoot 'python-dependencies'
    New-Item -ItemType Directory -Path $wheelhouse,$dependencyRoot -Force | Out-Null

    foreach ($artifact in $validated.Artifacts) {
        $destination = Join-Path $wheelhouse $artifact.FileName
        try {
            Invoke-WebRequest -Uri $artifact.Url -OutFile $destination -MaximumRedirection 0 -TimeoutSec 90 -ErrorAction Stop
        } catch {
            Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            throw 'VALIDATION_DEPENDENCY_DOWNLOAD_FAILED'
        }
        $actualSize = (Get-Item -LiteralPath $destination -ErrorAction Stop).Length
        if ($actualSize -ne $artifact.SizeBytes) { throw 'VALIDATION_DEPENDENCY_SIZE_MISMATCH' }
        $actualSha = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualSha -ne $artifact.Sha256) { throw 'VALIDATION_DEPENDENCY_HASH_MISMATCH' }
    }

    $selectedPython = Select-ValidationPython
    $pipArgs = @($selectedPython.PrefixArgs) + @(
        '-m','pip','install','--isolated','--disable-pip-version-check','--no-index',
        '--find-links',$wheelhouse,'--require-hashes','--only-binary=:all:',
        '--no-compile','--target',$dependencyRoot,'-r',$validated.LockPath
    )
    & $selectedPython.Executable @pipArgs 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'VALIDATION_DEPENDENCY_INSTALL_FAILED' }

    return [pscustomobject]@{
        DependencyRoot = $dependencyRoot
        PythonExecutable = $selectedPython.Executable
        PythonPrefixArgs = @($selectedPython.PrefixArgs)
        PythonVersion = $selectedPython.Version
        WheelCount = $validated.Artifacts.Count
    }
}

if ($SelfTest) {
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ('validation-wheelhouse-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixture -Force | Out-Null
    try {
        $lockPath = Join-Path $fixture 'requirements-windows.lock'
        [IO.File]::WriteAllText($lockPath,("fixture-lock" + [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        $lockHash = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $validManifest = [ordered]@{
            schema = 'validation.python-wheelhouse.v1'
            lock_file = 'requirements-windows.lock'
            lock_file_sha256 = $lockHash
            artifacts = @(
                [ordered]@{
                    filename = 'fixture-1.0-py3-none-any.whl'
                    url = 'https://files.pythonhosted.org/packages/test/fixture-1.0-py3-none-any.whl'
                    sha256 = ('0' * 64)
                    size_bytes = 1
                }
            )
        }
        $manifestPath = Join-Path $fixture 'validation-python-wheelhouse.json'
        $validManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
        $resolved = Read-ValidationWheelhouseManifest -ManifestPath $manifestPath
        if ($resolved.Artifacts.Count -ne 1 -or $resolved.LockPath -ne $lockPath) {
            throw 'SELFTEST_VALID_WHEELHOUSE_MANIFEST_NOT_ACCEPTED'
        }
        Write-Output 'SELFTEST_PASS_WHEELHOUSE_LOCK_AND_HOST_ALLOWLIST'

        $invalidManifest = $validManifest | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        $invalidManifest.artifacts[0].url = 'https://attacker.example/packages/fixture-1.0-py3-none-any.whl'
        $invalidManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8
        $rejected = $false
        try { Read-ValidationWheelhouseManifest -ManifestPath $manifestPath | Out-Null }
        catch { $rejected = ([string]$_.Exception.Message -eq 'VALIDATION_DEPENDENCY_WHEEL_URL_NOT_ALLOWLISTED') }
        if (-not $rejected) { throw 'SELFTEST_NON_ALLOWLISTED_HOST_NOT_REJECTED' }
        Write-Output 'SELFTEST_PASS_WHEELHOUSE_HOST_DENY'

        [IO.File]::WriteAllText($lockPath,("tampered" + [Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        $rejectedLock = $false
        try { Read-ValidationWheelhouseManifest -ManifestPath $manifestPath | Out-Null }
        catch { $rejectedLock = ([string]$_.Exception.Message -eq 'VALIDATION_DEPENDENCY_LOCK_HASH_MISMATCH') }
        if (-not $rejectedLock) { throw 'SELFTEST_LOCK_TAMPER_NOT_REJECTED' }
        Write-Output 'SELFTEST_PASS_WHEELHOUSE_LOCK_TAMPER_REJECTION'
        Write-Output 'VALIDATION_DEPENDENCY_BOOTSTRAP_SELFTEST_PASS'
    }
    finally {
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
    }
}
