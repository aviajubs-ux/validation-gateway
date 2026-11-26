[CmdletBinding()]
param(
    [ValidateSet('01','02','03')]
    [string]$Lane,
    [switch]$SelfTest
)

if (-not $SelfTest -and [string]::IsNullOrWhiteSpace($Lane)) {
    throw 'LANE_REQUIRED'
}
if ($SelfTest -and -not [string]::IsNullOrWhiteSpace($Lane)) {
    throw 'SELFTEST_LANE_NOT_ALLOWED'
}

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$startedUtc = [DateTime]::UtcNow.ToString('o')

$runRoot = Join-Path $env:RUNNER_TEMP 'validation'
$payloadRoot = Join-Path $runRoot 'payload'
$evidenceRoot = Join-Path $runRoot 'evidence'
$buildRoot = Join-Path $runRoot 'build'
$candidateOutputRoot = Join-Path $runRoot 'candidate-output'
$archivePath = Join-Path $runRoot 'source.zip'

# Read bootstrap inputs once. Never pass these values to any candidate process.
$sourceUrl = $env:SOURCE_URL
$expectedHash = $env:SOURCE_SHA256
$evidenceKeyB64 = $env:EVIDENCE_KEY_B64

$secretEnvironmentNames = @(
    'SOURCE_URL','SOURCE_SHA256','EVIDENCE_KEY_B64',
    'SOURCE_URL_01','SOURCE_SHA256_01','EVIDENCE_KEY_B64_01',
    'SOURCE_URL_02','SOURCE_SHA256_02','EVIDENCE_KEY_B64_02',
    'SOURCE_URL_03','SOURCE_SHA256_03','EVIDENCE_KEY_B64_03'
)
foreach ($name in $secretEnvironmentNames) {
    [Environment]::SetEnvironmentVariable($name,$null,'Process')
    Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
}

$status = 'BLOCKED'
$exitCode = 1
$actualHash = $null
$sourceHashVerified = $false
$os = $null
$candidateUserName = "v" + [Guid]::NewGuid().ToString('N').Substring(0,12)
$candidatePassword = $null
$candidateSid = $null
$candidateProfile = $null
$candidateTemp = $null
$firewallRuleNames = @()
$stepOutputPath = $env:GITHUB_OUTPUT

New-Item -ItemType Directory -Path $runRoot,$evidenceRoot,$candidateOutputRoot -Force | Out-Null


# Bounded concurrent pipe capture. The readers continue draining the pipes while
# retaining at most the configured characters per stream. The first overflow or
# timeout terminates the complete process tree before the script reports failure.
if ($null -eq ('Teli.Validation.BoundedProcessCapture' -as [type])) {
    $boundedCaptureSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Teli.Validation
{
    public sealed class BoundedProcessCaptureResult
    {
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public bool TimedOut { get; set; }
        public bool OutputLimitExceeded { get; set; }
        public bool ReaderCleanupFailed { get; set; }
    }

    public static class BoundedProcessCapture
    {
        public static BoundedProcessCaptureResult WaitForExit(
            Process process,
            int timeoutMilliseconds,
            int maximumCharactersPerStream)
        {
            if (process == null || timeoutMilliseconds < 1 ||
                maximumCharactersPerStream < 1024)
            {
                throw new ArgumentOutOfRangeException("Invalid capture limits.");
            }

            int exceeded = 0;
            Action onExceeded = () => Interlocked.Exchange(ref exceeded, 1);
            Task<string> stdoutTask = CaptureAsync(
                process.StandardOutput, maximumCharactersPerStream, onExceeded);
            Task<string> stderrTask = CaptureAsync(
                process.StandardError, maximumCharactersPerStream, onExceeded);

            var timer = Stopwatch.StartNew();
            bool timedOut = false;
            bool outputLimitExceeded = false;

            while (!process.HasExited)
            {
                if (Volatile.Read(ref exceeded) != 0)
                {
                    outputLimitExceeded = true;
                    break;
                }
                if (timer.ElapsedMilliseconds >= timeoutMilliseconds)
                {
                    timedOut = true;
                    break;
                }
                Thread.Sleep(20);
            }

            if (timedOut || outputLimitExceeded)
            {
                try
                {
                    if (!process.HasExited) process.Kill(true);
                }
                catch
                {
                    if (!process.HasExited)
                        throw new InvalidOperationException("CANDIDATE_PROCESS_TREE_KILL_FAILED");
                }

                if (!process.WaitForExit(5000))
                {
                    try { process.Kill(true); } catch { }
                    if (!process.WaitForExit(5000))
                        throw new InvalidOperationException("CANDIDATE_PROCESS_DID_NOT_EXIT");
                }
            }
            else
            {
                process.WaitForExit();
            }

            bool readersCompleted = false;
            try
            {
                readersCompleted = Task.WaitAll(
                    new Task[] { stdoutTask, stderrTask }, 5000);
            }
            catch
            {
                readersCompleted = stdoutTask.IsCompleted && stderrTask.IsCompleted;
            }

            if (!readersCompleted)
            {
                try { process.StandardOutput.Close(); } catch { }
                try { process.StandardError.Close(); } catch { }
                try
                {
                    readersCompleted = Task.WaitAll(
                        new Task[] { stdoutTask, stderrTask }, 5000);
                }
                catch
                {
                    readersCompleted = stdoutTask.IsCompleted && stderrTask.IsCompleted;
                }
            }

            if (!readersCompleted)
                throw new InvalidOperationException("CANDIDATE_OUTPUT_READER_DID_NOT_STOP");

            return new BoundedProcessCaptureResult
            {
                StandardOutput = stdoutTask.GetAwaiter().GetResult(),
                StandardError = stderrTask.GetAwaiter().GetResult(),
                TimedOut = timedOut,
                OutputLimitExceeded = outputLimitExceeded || Volatile.Read(ref exceeded) != 0,
                ReaderCleanupFailed = false
            };
        }

        private static async Task<string> CaptureAsync(
            TextReader reader,
            int maximumCharacters,
            Action onExceeded)
        {
            char[] buffer = new char[8192];
            var retained = new StringBuilder(Math.Min(maximumCharacters, 65536));
            int stored = 0;

            try
            {
                while (true)
                {
                    int count = await reader.ReadAsync(
                        buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (count == 0) break;

                    int remaining = Math.Max(0, maximumCharacters - stored);
                    int keep = Math.Min(count, remaining);
                    if (keep > 0)
                    {
                        retained.Append(buffer, 0, keep);
                        stored += keep;
                    }
                    if (keep < count) onExceeded();
                }
            }
            catch (ObjectDisposedException) { }
            catch (IOException) { }

            return retained.ToString();
        }
    }
}
'@
    Add-Type -TypeDefinition $boundedCaptureSource -Language CSharp
}

function Stop-CandidateProcessTree {
    param([Parameter(Mandatory=$true)][int]$RootProcessId)

    $known = [System.Collections.Generic.HashSet[int]]::new()
    [void]$known.Add($RootProcessId)

    # Discover descendants, including detached child processes, before cleanup.
    for ($round = 0; $round -lt 12; $round++) {
        $added = $false
        $processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        foreach ($item in $processes) {
            $parentId = [int]$item.ParentProcessId
            $processId = [int]$item.ProcessId
            if ($known.Contains($parentId) -and -not $known.Contains($processId)) {
                [void]$known.Add($processId)
                $added = $true
            }
        }
        if (-not $added) { break }
    }

    # Stop deepest descendants first. Do not stop the runner agent or this shell.
    $ids = @($known | Where-Object { $_ -ne $RootProcessId } | Sort-Object -Descending)
    foreach ($processId in $ids) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-CandidateSandbox {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'SANDBOX_ADMIN_REQUIRED'
    }

    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($profiles.Count -lt 3 -or @($profiles | Where-Object { $_.Enabled -ne 'True' }).Count -gt 0) {
        throw 'SANDBOX_FIREWALL_NOT_ENABLED'
    }

    $randomBytes = [byte[]]::new(48)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($randomBytes) } finally { $rng.Dispose() }
    $passwordText = [Convert]::ToBase64String($randomBytes) + 'Aa1!'
    [Array]::Clear($randomBytes,0,$randomBytes.Length)
    $script:candidatePassword = ConvertTo-SecureString -String $passwordText -AsPlainText -Force
    $passwordText = $null

    $newUser = New-LocalUser -Name $script:candidateUserName -Password $script:candidatePassword -Description 'Ephemeral isolated validation identity' -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
    $script:candidateSid = $newUser.SID.Value

    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545' -ErrorAction Stop
    $isStandardUser = @(Get-LocalGroupMember -Group $usersGroup.Name -ErrorAction Stop | Where-Object { $_.SID.Value -eq $script:candidateSid }).Count -gt 0
    if (-not $isStandardUser) {
        Add-LocalGroupMember -Group $usersGroup.Name -Member $script:candidateUserName -ErrorAction Stop
    }

    $adminsGroup = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
    $isAdministrator = @(Get-LocalGroupMember -Group $adminsGroup.Name -ErrorAction Stop | Where-Object { $_.SID.Value -eq $script:candidateSid }).Count -gt 0
    if ($isAdministrator) { throw 'SANDBOX_CANDIDATE_USER_IS_ADMIN' }

    $principalSddl = "D:(A;;GA;;;$($script:candidateSid))"
    $suffix = [Guid]::NewGuid().ToString('N')
    $outRule = "validation-candidate-egress-$suffix"
    $inRule = "validation-candidate-ingress-$suffix"
    $script:firewallRuleNames = @($outRule,$inRule)

    New-NetFirewallRule -Name $outRule -DisplayName $outRule -Direction Outbound -Action Block -Profile Any -RemoteAddress Any -LocalUser $principalSddl -Enabled True -ErrorAction Stop | Out-Null
    New-NetFirewallRule -Name $inRule -DisplayName $inRule -Direction Inbound -Action Block -Profile Any -RemoteAddress Any -LocalUser $principalSddl -Enabled True -ErrorAction Stop | Out-Null

    $outRuleState = Get-NetFirewallRule -Name $outRule -ErrorAction Stop
    $outSecurity = $outRuleState | Get-NetFirewallSecurityFilter -ErrorAction Stop
    if ($outRuleState.Action -ne 'Block' -or $outRuleState.Enabled -ne 'True' -or $outRuleState.Direction -ne 'Outbound' -or -not ($outSecurity.LocalUser -match [Regex]::Escape($script:candidateSid))) {
        throw 'SANDBOX_EGRESS_RULE_VERIFICATION_FAILED'
    }

    $script:candidateProfile = Join-Path $env:SystemDrive ("Users\" + $script:candidateUserName)
    $script:candidateTemp = Join-Path $runRoot 'candidate-temp'
    New-Item -ItemType Directory -Path $script:candidateTemp -Force | Out-Null

    $sidAceTraverse = "*$($script:candidateSid):(X)"
    $sidAceModify = "*$($script:candidateSid):(OI)(CI)M"
    $icacls = Join-Path $env:SystemRoot 'System32/icacls.exe'
    & $icacls $env:RUNNER_TEMP /grant $sidAceTraverse /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SANDBOX_TEMP_TRAVERSE_ACL_FAILED' }
    # Candidate may traverse the scratch root but must not modify trusted evidence,
    # bootstrap inputs, encryption outputs, or the runner's result files.
    & $icacls $runRoot /grant $sidAceTraverse /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SANDBOX_RUNROOT_TRAVERSE_ACL_FAILED' }
    foreach ($writablePath in @($payloadRoot,$buildRoot,$candidateOutputRoot,$script:candidateTemp)) {
        New-Item -ItemType Directory -Path $writablePath -Force | Out-Null
        & $icacls $writablePath /grant $sidAceModify /T /C /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SANDBOX_SCOPED_WRITE_ACL_FAILED' }
    }
}

function Copy-CandidateEvidenceSafely {
    if (-not (Test-Path -LiteralPath $candidateOutputRoot -PathType Container)) { return }
    $root = [IO.Path]::GetFullPath($candidateOutputRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $items = @(Get-ChildItem -LiteralPath $candidateOutputRoot -Recurse -Force -ErrorAction Stop)
    if ($items.Count -gt 10000) { throw 'CANDIDATE_EVIDENCE_FILE_COUNT_LIMIT' }
    $totalBytes = [int64]0
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'CANDIDATE_EVIDENCE_REPARSE_POINT_REJECTED' }
        if ($item.PSIsContainer) { continue }
        if ($item.Length -gt 50MB) { throw 'CANDIDATE_EVIDENCE_FILE_SIZE_LIMIT' }
        $totalBytes += [int64]$item.Length
        if ($totalBytes -gt 200MB) { throw 'CANDIDATE_EVIDENCE_TOTAL_SIZE_LIMIT' }
        $full = [IO.Path]::GetFullPath($item.FullName)
        if (-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'CANDIDATE_EVIDENCE_PATH_ESCAPE' }
        $relative = $full.Substring($root.Length)
        $destination = Join-Path $evidenceRoot $relative
        $destinationParent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
        [IO.File]::Copy($full,$destination,$true)
    }
}

function Remove-CandidateSandbox {
    foreach ($ruleName in $script:firewallRuleNames) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    }
    $script:firewallRuleNames = @()
    if ($script:candidateUserName) {
        Remove-LocalUser -Name $script:candidateUserName -ErrorAction SilentlyContinue
    }
    if ($script:candidatePassword) {
        $script:candidatePassword.Dispose()
        $script:candidatePassword = $null
    }
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory=$true)][string]$Executable,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$LogPath,
        [string]$WorkingDirectory = $runRoot,
        [ValidateRange(1,18000)][int]$TimeoutSeconds = 1800,
        [ValidateRange(1024,16777216)][int]$MaxOutputCharsPerStream = 8388608
    )

    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw 'CANDIDATE_EXECUTABLE_NOT_FOUND'
    }
    if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
        throw 'CANDIDATE_WORKING_DIRECTORY_NOT_FOUND'
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    # Start as the isolated temporary identity for validation runs.
    # Self-tests deliberately use the current hosted-runner identity and no secrets.
    if ($null -ne $script:candidatePassword -and -not [string]::IsNullOrWhiteSpace($script:candidateUserName)) {
        $psi.UserName = $script:candidateUserName
        $psi.Domain = $env:COMPUTERNAME
        $psi.Password = $script:candidatePassword
        $psi.LoadUserProfile = $true
    }

    # Candidate code receives only operating-system and toolchain variables.
    # No GITHUB_*, ACTIONS_*, RUNNER_*, token, URL, hash, or encryption-key values.
    $safeEnvironment = @(
        'PATH','PATHEXT','SystemRoot','WINDIR','SystemDrive','COMPUTERNAME','ProgramFiles','ProgramFiles(x86)','ProgramW6432',
        'CommonProgramFiles','CommonProgramFiles(x86)','ProgramData','ComSpec',
        'PROCESSOR_ARCHITECTURE','PROCESSOR_IDENTIFIER','NUMBER_OF_PROCESSORS',
        'VSINSTALLDIR','VCINSTALLDIR','VCToolsInstallDir','VCToolsRedistDir',
        'VisualStudioVersion','WindowsSdkDir','WindowsSDKVersion','UniversalCRTSdkDir',
        'UCRTVersion','INCLUDE','LIB','LIBPATH','VSCMD_VER','VSCMD_ARG_TGT_ARCH',
        'VSCMD_ARG_HOST_ARCH','DevEnvDir','MSBuildExtensionsPath','MSBuildSDKsPath',
        'DOTNET_ROOT','DOTNET_ROOT_X64','DOTNET_ROOT_X86'
    )
    $psi.Environment.Clear()
    foreach ($name in $safeEnvironment) {
        $value = [Environment]::GetEnvironmentVariable($name,'Process')
        if ($null -ne $value) { $psi.Environment[$name] = $value }
    }

    $profileHome = $script:candidateProfile
    if ([string]::IsNullOrWhiteSpace($profileHome)) { $profileHome = $env:USERPROFILE }
    $effectiveUserName = $script:candidateUserName
    if ([string]::IsNullOrWhiteSpace($effectiveUserName)) { $effectiveUserName = [Environment]::UserName }
    $effectiveTemp = $script:candidateTemp
    if ([string]::IsNullOrWhiteSpace($effectiveTemp)) { $effectiveTemp = $env:TEMP }

    $psi.Environment['USERNAME'] = $effectiveUserName
    $psi.Environment['USERDOMAIN'] = $env:COMPUTERNAME
    $psi.Environment['USERPROFILE'] = $profileHome
    $psi.Environment['HOME'] = $profileHome
    $psi.Environment['HOMEDRIVE'] = $env:SystemDrive
    $psi.Environment['HOMEPATH'] = $profileHome.Substring($env:SystemDrive.Length)
    $psi.Environment['TEMP'] = $effectiveTemp
    $psi.Environment['TMP'] = $effectiveTemp
    $psi.Environment['APPDATA'] = Join-Path $profileHome 'AppData/Roaming'
    $psi.Environment['LOCALAPPDATA'] = Join-Path $profileHome 'AppData/Local'
    $psi.Environment['PSModulePath'] = @(
        (Join-Path $env:ProgramFiles 'PowerShell/Modules'),
        (Join-Path $env:ProgramFiles 'WindowsPowerShell/Modules'),
        (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules')
    ) -join ';'

    foreach ($argument in $Arguments) {
        [void]$psi.ArgumentList.Add([string]$argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $processId = 0

    try {
        if (-not $process.Start()) { throw 'CANDIDATE_PROCESS_START_FAILED' }
        $processId = $process.Id

        $capture = [Teli.Validation.BoundedProcessCapture]::WaitForExit(
            $process,
            [int]($TimeoutSeconds * 1000),
            $MaxOutputCharsPerStream
        )

        $utf8 = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText(($LogPath + '.stdout.log'),$capture.StandardOutput,$utf8)
        [System.IO.File]::WriteAllText(($LogPath + '.stderr.log'),$capture.StandardError,$utf8)
        $combined = $capture.StandardOutput + [Environment]::NewLine +
            '--- STDERR ---' + [Environment]::NewLine + $capture.StandardError
        [System.IO.File]::WriteAllText($LogPath,$combined,$utf8)

        if ($capture.OutputLimitExceeded) { throw 'CANDIDATE_OUTPUT_LIMIT_EXCEEDED' }
        if ($capture.TimedOut) { throw 'CANDIDATE_PROCESS_TIMEOUT' }
        if ($capture.ReaderCleanupFailed) { throw 'CANDIDATE_OUTPUT_READER_INCOMPLETE' }

        return [int]$process.ExitCode
    }
    finally {
        if ($processId -gt 0) {
            Stop-CandidateProcessTree -RootProcessId $processId
        }
        $process.Dispose()
        $psi = $null
    }
}


if ($SelfTest) {
    $selfTestRoot = Join-Path $env:RUNNER_TEMP ("validation-gateway-selftest-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $selfTestRoot -Force | Out-Null
    $script:candidateUserName = $null
    $script:candidatePassword = $null
    $script:candidateProfile = $env:USERPROFILE
    $script:candidateTemp = Join-Path $selfTestRoot 'temp'
    New-Item -ItemType Directory -Path $script:candidateTemp -Force | Out-Null
    $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source

    try {
        $streamLog = Join-Path $selfTestRoot 'streams.log'
        $streamCode = '[Console]::Out.Write("STDOUT_SENTINEL"); [Console]::Error.Write("STDERR_SENTINEL"); exit 0'
        $streamExit = Invoke-Captured -Executable $pwsh -Arguments @(
            '-NoLogo','-NoProfile','-NonInteractive','-Command',$streamCode
        ) -LogPath $streamLog -WorkingDirectory $selfTestRoot -TimeoutSeconds 15 -MaxOutputCharsPerStream 4096
        $capturedOut = [IO.File]::ReadAllText($streamLog + '.stdout.log')
        $capturedErr = [IO.File]::ReadAllText($streamLog + '.stderr.log')
        if ($streamExit -ne 0 -or $capturedOut -ne 'STDOUT_SENTINEL' -or $capturedErr -ne 'STDERR_SENTINEL') {
            throw 'SELFTEST_STDOUT_STDERR_ISOLATION_FAILED'
        }
        Write-Output 'SELFTEST_PASS_STDOUT_STDERR'

        $exitCode = Invoke-Captured -Executable $pwsh -Arguments @(
            '-NoLogo','-NoProfile','-NonInteractive','-Command','exit 17'
        ) -LogPath (Join-Path $selfTestRoot 'exit-code.log') -WorkingDirectory $selfTestRoot -TimeoutSeconds 15
        if ($exitCode -ne 17) { throw 'SELFTEST_EXIT_CODE_NOT_PRESERVED' }
        Write-Output 'SELFTEST_PASS_EXIT_CODE'

        $timeoutObserved = $false
        try {
            [void](Invoke-Captured -Executable $pwsh -Arguments @(
                '-NoLogo','-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30'
            ) -LogPath (Join-Path $selfTestRoot 'timeout.log') -WorkingDirectory $selfTestRoot -TimeoutSeconds 2 -MaxOutputCharsPerStream 4096)
        } catch {
            if ($_.Exception.Message -eq 'CANDIDATE_PROCESS_TIMEOUT') { $timeoutObserved = $true } else { throw }
        }
        if (-not $timeoutObserved) { throw 'SELFTEST_TIMEOUT_NOT_ENFORCED' }
        Write-Output 'SELFTEST_PASS_TIMEOUT'

        $outputLimitObserved = $false
        try {
            $floodCode = '$x = "0123456789" * 100000; [Console]::Out.Write($x); [Console]::Out.Flush(); Start-Sleep -Seconds 30'
            [void](Invoke-Captured -Executable $pwsh -Arguments @(
                '-NoLogo','-NoProfile','-NonInteractive','-Command',$floodCode
            ) -LogPath (Join-Path $selfTestRoot 'output-limit.log') -WorkingDirectory $selfTestRoot -TimeoutSeconds 15 -MaxOutputCharsPerStream 4096)
        } catch {
            if ($_.Exception.Message -eq 'CANDIDATE_OUTPUT_LIMIT_EXCEEDED') { $outputLimitObserved = $true } else { throw }
        }
        if (-not $outputLimitObserved) { throw 'SELFTEST_OUTPUT_LIMIT_NOT_ENFORCED' }
        Write-Output 'SELFTEST_PASS_OUTPUT_LIMIT'

        $childPidFile = Join-Path $selfTestRoot 'child.pid'
        $childScriptTemplate = '$child = Start-Process -FilePath ''{0}'' -ArgumentList @(''-NoLogo'',''-NoProfile'',''-Command'',''Start-Sleep -Seconds 60'') -PassThru -WindowStyle Hidden; [IO.File]::WriteAllText(''{1}'',[string]$child.Id); Start-Sleep -Seconds 60'
        $childScript = $childScriptTemplate -f $pwsh.Replace("'","''"),$childPidFile.Replace("'","''")
        $treeTimeoutObserved = $false
        try {
            [void](Invoke-Captured -Executable $pwsh -Arguments @(
                '-NoLogo','-NoProfile','-NonInteractive','-Command',$childScript
            ) -LogPath (Join-Path $selfTestRoot 'process-tree.log') -WorkingDirectory $selfTestRoot -TimeoutSeconds 3 -MaxOutputCharsPerStream 4096)
        } catch {
            if ($_.Exception.Message -eq 'CANDIDATE_PROCESS_TIMEOUT') { $treeTimeoutObserved = $true } else { throw }
        }
        if (-not $treeTimeoutObserved -or -not (Test-Path -LiteralPath $childPidFile)) {
            throw 'SELFTEST_PROCESS_TREE_FIXTURE_FAILED'
        }
        $childPid = [int](Get-Content -LiteralPath $childPidFile -Raw)
        $childAlive = $false
        for ($i = 0; $i -lt 10; $i++) {
            if (Get-Process -Id $childPid -ErrorAction SilentlyContinue) {
                Start-Sleep -Milliseconds 200
            } else {
                $childAlive = $false
                break
            }
            $childAlive = $true
        }
        if ($childAlive) { throw 'SELFTEST_DESCENDANT_SURVIVED_TIMEOUT' }
        Write-Output 'SELFTEST_PASS_PROCESS_TREE_CLEANUP'
        Write-Output 'VALIDATION_GATEWAY_SELFTEST_PASS'
        exit 0
    }
    finally {
        if (Test-Path -LiteralPath $selfTestRoot) {
            Remove-Item -LiteralPath $selfTestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $runRoot) {
            Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop

    if ([string]::IsNullOrWhiteSpace($sourceUrl)) { throw 'CONFIG_SOURCE_URL_MISSING' }
    if ($expectedHash -notmatch '^[0-9a-fA-F]{64}$') { throw 'CONFIG_SHA256_INVALID' }
    if ([string]::IsNullOrWhiteSpace($evidenceKeyB64)) { throw 'CONFIG_EVIDENCE_KEY_MISSING' }

    $keyCheck = [Convert]::FromBase64String($evidenceKeyB64)
    if ($keyCheck.Length -ne 32) { throw 'CONFIG_EVIDENCE_KEY_LENGTH_INVALID' }
    [Array]::Clear($keyCheck,0,$keyCheck.Length)
    $keyCheck = $null
    $evidenceKeyB64 = $null

    # The signed URL is used only by the bootstrap downloader.
    Invoke-WebRequest -Uri $sourceUrl -OutFile $archivePath -MaximumRedirection 5 -ErrorAction Stop
    $sourceUrl = $null

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash.ToLowerInvariant()) { throw 'SOURCE_SHA256_MISMATCH' }
    $sourceHashVerified = $true
    $expectedHash = $null

    Expand-Archive -LiteralPath $archivePath -DestinationPath $payloadRoot -Force

    # Candidate code runs as a temporary standard user with user-scoped inbound
    # and outbound network blocks. No checkout token or GitHub credential is used.
    foreach ($name in $secretEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name,$null,'Process')
        Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
    }
    $sourceUrl = $null
    $expectedHash = $null
    $evidenceKeyB64 = $null
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Initialize-CandidateSandbox

    $pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
    $egressProbe = '$client = $null; try { $client = [Net.Sockets.TcpClient]::new(); $a = $client.BeginConnect("1.1.1.1",443,$null,$null); if ($a.AsyncWaitHandle.WaitOne(2500) -and $client.Connected) { exit 23 }; exit 0 } catch { exit 0 } finally { if ($client) { $client.Dispose() } }'
    $probeExit = Invoke-Captured -Executable $pwsh -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-Command',$egressProbe) -LogPath (Join-Path $evidenceRoot 'network-isolation-probe.log') -TimeoutSeconds 10 -MaxOutputCharsPerStream 4096
    if ($probeExit -ne 0) { throw 'SANDBOX_OUTBOUND_NETWORK_NOT_BLOCKED' }

    if ($Lane -eq '01') {
        $runnerCandidates = @(Get-ChildItem -LiteralPath $payloadRoot -Filter 'Invoke-*-WindowsMSVC.ps1' -File -Recurse)
        if ($runnerCandidates.Count -ne 1) { throw 'PACKAGE_ENTRYPOINT_LAYOUT_INVALID' }

        $runner = $runnerCandidates[0].FullName
        $packageRoot = $runnerCandidates[0].Directory.FullName
        $archiveCandidates = @(Get-ChildItem -LiteralPath $packageRoot -Filter '*_CANDIDATE_*.zip' -File)
        if ($archiveCandidates.Count -ne 1) { throw 'PACKAGE_INPUT_LAYOUT_INVALID' }

        $exitCode = Invoke-Captured -Executable $pwsh -Arguments @(
            '-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',$runner,'-CandidateArchive',$archiveCandidates[0].FullName,
            '-EvidenceParent',$candidateOutputRoot,'-Configuration','Release','-Parallel','2'
        ) -LogPath (Join-Path $evidenceRoot 'candidate-runner.log') -WorkingDirectory $packageRoot -TimeoutSeconds 14400
        Copy-CandidateEvidenceSafely

        if ($exitCode -eq 0) { $status = 'PASS_LANE_01_CANDIDATE_VALIDATION' }
        else { $status = 'FAIL_LANE_01_CANDIDATE_VALIDATION' }
    }
    elseif ($Lane -eq '02') {
        $cmakeCandidates = @(Get-ChildItem -LiteralPath $payloadRoot -Filter 'CMakeLists.txt' -File -Recurse |
            Where-Object {
                (Test-Path -LiteralPath (Join-Path $_.Directory.FullName 'src') -PathType Container) -and
                (Test-Path -LiteralPath (Join-Path $_.Directory.FullName 'include') -PathType Container) -and
                (Test-Path -LiteralPath (Join-Path $_.Directory.FullName 'tests') -PathType Container)
            })
        if ($cmakeCandidates.Count -ne 1) { throw 'PACKAGE_BUILD_ROOT_LAYOUT_INVALID' }
        $sourceRoot = $cmakeCandidates[0].Directory.FullName

        $cmake = (Get-Command cmake.exe -ErrorAction Stop).Source
        New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null

        $exitCode = Invoke-Captured -Executable $cmake -Arguments @(
            '-S',$sourceRoot,'-B',$buildRoot,
            '-DBUILD_TESTING=ON',
            '-DCMAKE_CONFIGURATION_TYPES=Release'
        ) -LogPath (Join-Path $evidenceRoot 'configure.log') -TimeoutSeconds 300
        if ($exitCode -ne 0) { throw 'BUILD_CONFIGURE_FAILED' }

        $exitCode = Invoke-Captured -Executable $cmake -Arguments @(
            '--build',$buildRoot,'--config','Release','--parallel','2','--target','ALL_BUILD'
        ) -LogPath (Join-Path $evidenceRoot 'build.log') -TimeoutSeconds 10800
        if ($exitCode -ne 0) { throw 'FULL_BUILD_FAILED' }

        $ctest = (Get-Command ctest.exe -ErrorAction Stop).Source
        $exitCode = Invoke-Captured -Executable $ctest -Arguments @(
            '--test-dir',$buildRoot,'-C','Release','-N'
        ) -LogPath (Join-Path $evidenceRoot 'test-discovery.log') -TimeoutSeconds 300
        if ($exitCode -ne 0) { throw 'TEST_DISCOVERY_FAILED' }

        $exitCode = Invoke-Captured -Executable $ctest -Arguments @(
            '--test-dir',$buildRoot,'-C','Release','--output-on-failure','--verbose',
            '--parallel','2','--timeout','300','--output-junit',(Join-Path $candidateOutputRoot 'ctest-junit.xml')
        ) -LogPath (Join-Path $evidenceRoot 'ctest-execution.log') -TimeoutSeconds 14400

        Copy-CandidateEvidenceSafely
        if ($exitCode -eq 0) { $status = 'PASS_LANE_02_BUILD_AND_TESTS' }
        else { $status = 'FAIL_LANE_02_BUILD_OR_TESTS' }
    }
    else {
        # Generic Windows-client package contract: exactly one runner under the package
        # must match run_*_integration_windows.py. No product-specific names are embedded
        # in this public execution infrastructure.
        $runnerCandidates = @(Get-ChildItem -LiteralPath $payloadRoot -Filter 'run_*_integration_windows.py' -File -Recurse)
        if ($runnerCandidates.Count -ne 1) { throw 'PACKAGE_ENTRYPOINT_LAYOUT_INVALID' }

        $runner = $runnerCandidates[0].FullName
        $projectRoot = $runnerCandidates[0].Directory.Parent.FullName
        $requiredSourceRoot = Join-Path $projectRoot 'source/active'
        if (!(Test-Path -LiteralPath $requiredSourceRoot -PathType Container)) {
            throw 'PACKAGE_SOURCE_LAYOUT_INVALID'
        }

        if ([int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) {
            $status = 'NOT_RUN_REQUIRED_CLIENT_OS_UNAVAILABLE'
            $exitCode = 0
            $platformEvidence = [ordered]@{
                status = $status
                os_build = $os.BuildNumber
                product_type = $os.ProductType
                required_client_os_proof = $false
                tests_executed = 0
                runner_entrypoint_count = 1
                reason = 'The hosted runner is not a supported Windows client OS; no client-OS security tests were executed.'
            }
            $platformEvidence | ConvertTo-Json -Depth 5 |
                Set-Content -LiteralPath (Join-Path $evidenceRoot 'platform-limit.json') -Encoding utf8
        }
        else {
            $python = (Get-Command python.exe -ErrorAction Stop).Source
            $runnerOutput = Join-Path $candidateOutputRoot 'windows-client'
            New-Item -ItemType Directory -Path $runnerOutput -Force | Out-Null
            $runnerLog = Join-Path $evidenceRoot 'windows-client-launch.log'
            $runnerExit = Invoke-Captured -Executable $python -Arguments @(
                $runner,'--project-root',$projectRoot,'--output-dir',$runnerOutput
            ) -LogPath $runnerLog -WorkingDirectory $projectRoot -TimeoutSeconds 1800

            $runnerStatus = 'RESULT_UNAVAILABLE'
            $testCounts = $null
            $resultPath = Join-Path $runnerOutput 'WINDOWS_LIFECYCLE_RESULT.json'
            if ((Test-Path -LiteralPath $resultPath -PathType Leaf) -and (Get-Item -LiteralPath $resultPath).Length -le 5MB) {
                try {
                    $runnerDocument = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($runnerDocument.status -is [string] -and $runnerDocument.status -match '^[A-Z0-9_]+$') {
                        $runnerStatus = $runnerDocument.status
                    }
                    $testCounts = [ordered]@{
                        total = [int]$runnerDocument.tests.total
                        passed = [int]$runnerDocument.tests.passed
                        skipped = [int]$runnerDocument.tests.skipped
                        failures = [int]$runnerDocument.tests.failures
                        errors = [int]$runnerDocument.tests.errors
                    }
                } catch {
                    $runnerStatus = 'RESULT_PARSE_FAILED'
                }
            }

            Copy-CandidateEvidenceSafely
            $summary = [ordered]@{
                schema = 'validation.gateway.windows_client_result.v1'
                runner_status = $runnerStatus
                runner_exit_code = [int]$runnerExit
                test_counts = $testCounts
                windows_client_gate = $true
                runner_os_label = 'windows-2025'
            }
            $summary | ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath (Join-Path $evidenceRoot 'runner-summary.json') -Encoding utf8

            if ($runnerExit -eq 0 -and $runnerStatus -eq 'PASS_WINDOWS11_STANDARD_USER' -and
                $null -ne $testCounts -and $testCounts.total -gt 0 -and
                $testCounts.skipped -eq 0 -and $testCounts.failures -eq 0 -and $testCounts.errors -eq 0) {
                $status = 'PASS_LANE_03_WINDOWS_CLIENT_VALIDATION'
                $exitCode = 0
            } else {
                $status = 'FAIL_OR_PARTIAL_LANE_03_PLATFORM_VALIDATION'
                $exitCode = 1
            }
        }
    }
}
catch {
    $safeCode = [string]$_.Exception.Message
    if ($safeCode -notmatch '^[A-Z0-9_]+$') { $safeCode = 'EXECUTION_ERROR' }
    [System.IO.File]::WriteAllText(
        (Join-Path $evidenceRoot 'failure-code.txt'),
        $safeCode,
        [System.Text.UTF8Encoding]::new($false)
    )
    if ($status -eq 'BLOCKED') { $status = 'BLOCKED_OR_FAILED' }
    if ($exitCode -eq 0 -and $status -ne 'NOT_RUN_REQUIRED_CLIENT_OS_UNAVAILABLE') { $exitCode = 1 }
}
finally {
    foreach ($name in $secretEnvironmentNames) {
        [Environment]::SetEnvironmentVariable($name,$null,'Process')
        Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
    }
    $sourceUrl = $null
    $expectedHash = $null
    $evidenceKeyB64 = $null
    Remove-CandidateSandbox

    $final = [ordered]@{
        schema = 'validation.gateway.execution.v2'
        lane = $Lane
        status = $status
        exit_code = $exitCode
        source_sha256_actual = $actualHash
        source_sha256_verified = $sourceHashVerified
        operating_system = if ($os) { $os.Caption } else { 'UNKNOWN' }
        os_build = if ($os) { $os.BuildNumber } else { 'UNKNOWN' }
        os_product_type = if ($os) { $os.ProductType } else { 'UNKNOWN' }
        required_client_os_proof = ($null -ne $os -and [int]$os.ProductType -eq 1 -and [int]$os.BuildNumber -ge 22000)
        runner_label = 'windows-2025'
        candidate_secret_environment_variables_removed = $true
        started_utc = $startedUtc
        completed_utc = [DateTime]::UtcNow.ToString('o')
    }
    $final | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $evidenceRoot 'execution-result.json') -Encoding utf8
    if ($stepOutputPath) { Add-Content -LiteralPath $stepOutputPath -Value ("status={0}" -f $status) }
}

if ($exitCode -ne 0) { exit 1 }
exit 0
