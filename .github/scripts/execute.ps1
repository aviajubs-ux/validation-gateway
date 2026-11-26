[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('01','02','03')]
    [string]$Lane
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$startedUtc = [DateTime]::UtcNow.ToString('o')

$runRoot = Join-Path $env:RUNNER_TEMP 'validation'
$payloadRoot = Join-Path $runRoot 'payload'
$evidenceRoot = Join-Path $runRoot 'evidence'
$buildRoot = Join-Path $runRoot 'build'
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

New-Item -ItemType Directory -Path $runRoot,$evidenceRoot -Force | Out-Null

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
    New-Item -ItemType Directory -Path $script:candidateProfile,$script:candidateTemp -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:candidateProfile 'AppData\Roaming'),(Join-Path $script:candidateProfile 'AppData\Local') -Force | Out-Null

    $sidAceTraverse = "*$($script:candidateSid):(X)"
    $sidAceModify = "*$($script:candidateSid):(OI)(CI)M"
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $env:RUNNER_TEMP /grant $sidAceTraverse /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SANDBOX_TEMP_TRAVERSE_ACL_FAILED' }
    & $icacls $runRoot /grant $sidAceModify /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SANDBOX_RUNROOT_ACL_FAILED' }
    & $icacls $script:candidateProfile /grant $sidAceModify /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'SANDBOX_PROFILE_ACL_FAILED' }
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
        [string]$WorkingDirectory = $runRoot
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Executable
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UserName = $script:candidateUserName
    $psi.Domain = $env:COMPUTERNAME
    $psi.Password = $script:candidatePassword
    $psi.LoadUserProfile = $true

    # Candidate code receives only operating-system and toolchain variables.
    # No GITHUB_*, ACTIONS_*, RUNNER_*, token, URL, hash, or encryption-key values.
    $safeEnvironment = @(
        'PATH','PATHEXT','SystemRoot','WINDIR','ProgramFiles','ProgramFiles(x86)','ProgramW6432',
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
    $psi.Environment['USERNAME'] = $script:candidateUserName
    $psi.Environment['USERDOMAIN'] = $env:COMPUTERNAME
    $psi.Environment['USERPROFILE'] = $profileHome
    $psi.Environment['HOME'] = $profileHome
    $psi.Environment['HOMEDRIVE'] = $env:SystemDrive
    $psi.Environment['HOMEPATH'] = $profileHome.Substring($env:SystemDrive.Length)
    $psi.Environment['TEMP'] = $script:candidateTemp
    $psi.Environment['TMP'] = $script:candidateTemp
    $psi.Environment['APPDATA'] = Join-Path $profileHome 'AppDataRoaming'
    $psi.Environment['LOCALAPPDATA'] = Join-Path $profileHome 'AppDataLocal'
    $psi.Environment['PSModulePath'] = @(
        (Join-Path $env:ProgramFiles 'PowerShellModules'),
        (Join-Path $env:ProgramFiles 'WindowsPowerShellModules'),
        (Join-Path $env:SystemRoot 'System32WindowsPowerShell1.0Modules')
    ) -join ';'

    foreach ($argument in $Arguments) {
        [void]$psi.ArgumentList.Add([string]$argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $stdoutTask = $null
    $stderrTask = $null
    $processId = 0

    try {
        if (-not $process.Start()) { throw 'CANDIDATE_PROCESS_START_FAILED' }
        $processId = $process.Id
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $combined = $stdout + [Environment]::NewLine + '--- STDERR ---' + [Environment]::NewLine + $stderr
        [System.IO.File]::WriteAllText($LogPath,$combined,[System.Text.UTF8Encoding]::new($false))
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
    $probeExit = Invoke-Captured -Executable $pwsh -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-Command',$egressProbe) -LogPath (Join-Path $evidenceRoot 'network-isolation-probe.log')
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
            '-EvidenceParent',$evidenceRoot,'-Configuration','Release','-Parallel','2'
        ) -LogPath (Join-Path $evidenceRoot 'candidate-runner.log') -WorkingDirectory $packageRoot

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
        ) -LogPath (Join-Path $evidenceRoot 'configure.log')
        if ($exitCode -ne 0) { throw 'BUILD_CONFIGURE_FAILED' }

        $exitCode = Invoke-Captured -Executable $cmake -Arguments @(
            '--build',$buildRoot,'--config','Release','--parallel','2','--target','ALL_BUILD'
        ) -LogPath (Join-Path $evidenceRoot 'build.log')
        if ($exitCode -ne 0) { throw 'FULL_BUILD_FAILED' }

        $ctest = (Get-Command ctest.exe -ErrorAction Stop).Source
        $exitCode = Invoke-Captured -Executable $ctest -Arguments @(
            '--test-dir',$buildRoot,'-C','Release','-N'
        ) -LogPath (Join-Path $evidenceRoot 'test-discovery.log')
        if ($exitCode -ne 0) { throw 'TEST_DISCOVERY_FAILED' }

        $exitCode = Invoke-Captured -Executable $ctest -Arguments @(
            '--test-dir',$buildRoot,'-C','Release','--output-on-failure','--verbose',
            '--parallel','2','--timeout','300','--output-junit',(Join-Path $evidenceRoot 'ctest-junit.xml')
        ) -LogPath (Join-Path $evidenceRoot 'ctest-execution.log')

        if ($exitCode -eq 0) { $status = 'PASS_LANE_02_BUILD_AND_TESTS' }
        else { $status = 'FAIL_LANE_02_BUILD_OR_TESTS' }
    }
    else {
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
                os_caption = $os.Caption
                os_build = $os.BuildNumber
                product_type = $os.ProductType
                required_client_os_proof = $false
                tests_executed = 0
                reason = 'The hosted runner is not a supported Windows client OS; no client-OS security tests were executed.'
            }
            $platformEvidence | ConvertTo-Json -Depth 5 |
                Set-Content -LiteralPath (Join-Path $evidenceRoot 'platform-limit.json') -Encoding utf8
        }
        else {
            $python = (Get-Command python.exe -ErrorAction Stop).Source
            $laneOutputEvidence = Join-Path $evidenceRoot 'system'
            New-Item -ItemType Directory -Path $laneOutputEvidence -Force | Out-Null
            $exitCode = Invoke-Captured -Executable $python -Arguments @(
                $runner,'--project-root',$projectRoot,'--output-dir',$laneOutputEvidence
            ) -LogPath (Join-Path $evidenceRoot 'system-launch.log') -WorkingDirectory $projectRoot

            if ($exitCode -eq 0) { $status = 'PASS_LANE_03_PLATFORM_VALIDATION' }
            else { $status = 'FAIL_OR_PARTIAL_LANE_03_PLATFORM_VALIDATION' }
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
