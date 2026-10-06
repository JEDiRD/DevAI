param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'))
$ErrorActionPreference = 'Stop'

# RH-D: a freshly formatted NTFS workspace volume came out owned by
# NT AUTHORITY\NETWORK SERVICE with an unprotected DACL, and the installer
# assumed a trusted root instead of establishing it. New-PrivateWorkspaceVolume
# now stamps the trusted owner explicitly (new volumes only) before the
# canonical policy is applied and re-verified.
#
# VHDX format/mount/ownership require elevation. Without it this harness
# reports the standard blocked marker (exit 0, no JSON verdict) instead of
# failing; canonical STEP7 runs it elevated.
$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
. (Join-Path $DeployRoot 'install-support.ps1')

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Output 'BLOCKED_PENDING_ELEVATED_EXECUTION:workspace volume provisioning requires elevation'
  exit 0
}

# Shape-valid witness SID. Policy functions validate the SHAPE only; no real
# service is created, read or required by any assertion below.
$serviceSid = 'S-1-5-80-1-2-3-4-5'
$report = [ordered]@{ cases = @(); passed = $false }

# Baseline for the atomicity case below: the harness must create no
# service/credential state itself. Pre-existing state (e.g. a real install
# under test on the same machine) is recorded, not mistaken for harness
# output; on a clean machine this is identical to asserting absence.
$svcBefore = [bool](Get-Service -Name DevAIWorker -ErrorAction Ignore)
$credBefore = Test-Path -LiteralPath (Join-Path $env:ProgramData 'DevAIWorker\credentials\worker.dpapi')
$probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('rhb-vol-probe-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($probeRoot) | Out-Null
$vhd1 = Join-Path $probeRoot 'workspace.vhdx'
$mount1 = Join-Path $probeRoot 'mount'
[IO.Directory]::CreateDirectory($mount1) | Out-Null
$vhd2 = $null
try {
  # 1+2. Fresh installer-created volume: normalized, then read back.
  $guid1 = New-PrivateWorkspaceVolume $vhd1 $mount1
  if ($guid1 -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') { throw 'VOLUME_GUID_MALFORMED' }
  $acl1 = Get-Acl -LiteralPath $guid1
  $owner1 = [string]$acl1.Owner
  $ownerSid1 = if ($owner1 -match '^S-1-5-') { $owner1 } else { ([Security.Principal.NTAccount]$owner1).Translate([Security.Principal.SecurityIdentifier]).Value }
  if ($ownerSid1 -ne 'S-1-5-32-544') { throw ('FRESH_ROOT_OWNER_UNEXPECTED:' + $ownerSid1) }
  if (-not $acl1.AreAccessRulesProtected) { throw 'FRESH_ROOT_NOT_PROTECTED' }
  $report.cases += 'FRESH_ROOT:NORMALIZED_AND_READ_BACK'

  # 3. Read-back validation is unblocked by the normalization.
  $null = Get-WorkspaceRootPolicy $vhd1 $mount1 $guid1 $serviceSid
  $report.cases += 'READBACK:UNBLOCKED'

  # 3b. The returned GUID is settled, not transient: the mount manager
  # resolves the new mount asynchronously, and the first read can name a
  # pre-filesystem volume that later gives way to the formatted volume
  # (RH-D: recorded GUID gone at first boot, worker died in
  # workspace_recovery with FileNotFoundError on the dangling mount).
  # New-PrivateWorkspaceVolume must not return until consecutive reads
  # agree, so a delayed re-read matches and still verifies.
  Start-Sleep -Seconds 10
  $guid1b = Get-WorkspaceMountGuid $mount1
  if ($guid1b -cne $guid1) { throw ('VOLUME_GUID_NOT_SETTLED:' + $guid1b) }
  $null = Get-VerifiedWorkspaceVolume $vhd1 $mount1 $guid1b
  $report.cases += 'SETTLED:RECORDED_GUID_STABLE_AND_VERIFIED'

  # 4. Full canonical policy: exact owner, exact ACE set, worker rights.
  $summary = Set-WorkspaceRootPolicy $vhd1 $mount1 $guid1 $serviceSid
  $descriptor = Get-NativeWorkspaceSecurity $guid1
  if ($descriptor.Owner.Value -ne 'S-1-5-32-544') { throw 'POLICY_OWNER_MISMATCH' }
  $sids = @($descriptor.DiscretionaryAcl | ForEach-Object { $_.SecurityIdentifier.Value } | Sort-Object -Unique)
  $expectedSids = @('S-1-5-18', 'S-1-5-32-544', $serviceSid) | Sort-Object -Unique
  if (($sids -join ',') -cne ($expectedSids -join ',')) { throw ('POLICY_SID_SET_MISMATCH:' + ($sids -join ',')) }
  if ($summary.foreign_allow_entries -ne 0) { throw 'POLICY_FOREIGN_ACE_PRESENT' }
  if (-not $summary.worker_can_list -or -not $summary.worker_can_modify) { throw 'POLICY_WORKER_RIGHTS_MISSING' }
  $report.cases += 'POLICY:EXACT_OWNER_GROUP_DACL_PROTECTION'

  # 5. Pre-existing volume with the same unexpected owner is REJECTED, never
  # seized or repaired. Build one manually (no normalization call).
  $vhd2 = Join-Path $probeRoot 'preexisting.vhdx'
  $mount2 = Join-Path $probeRoot 'mount2'
  [IO.Directory]::CreateDirectory($mount2) | Out-Null
  $create2 = Join-Path $probeRoot 'create2.txt'
  # Same geometry the product requires (verified: exactly 128 MiB, GPT,
  # DevAIWorkspace label): the rejection under test is about the OWNER,
  # so every other identity check must pass first.
  [IO.File]::WriteAllText($create2, ("create vdisk file=`"$vhd2`" maximum=128 type=fixed`r`nexit`r`n"))
  & "$env:SystemRoot/System32/diskpart.exe" /s $create2 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'PROBE_IMAGE_CREATION_FAILED' }
  Mount-DiskImage -ImagePath $vhd2 -NoDriveLetter | Out-Null
  $d2 = Get-Disk | Where-Object { $_.Location -eq $vhd2 }
  $i2 = Initialize-Disk -InputObject $d2 -PartitionStyle GPT -PassThru -Confirm:$false
  $p2 = New-Partition -InputObject $i2 -UseMaximumSize -AssignDriveLetter:$false
  $fmt2 = Format-Volume -Partition $p2 -FileSystem NTFS -NewFileSystemLabel DevAIWorkspace -Confirm:$false
  if ($fmt2.FileSystemType -ne 'NTFS') { throw 'PROBE_FORMAT_NOT_VERIFIED' }
  Add-PartitionAccessPath -InputObject $p2 -AccessPath ($mount2 + '\') -Confirm:$false
  $guid2 = Get-WorkspaceMountGuid $mount2
  # Force the observed unexpected state deterministically, whatever this
  # host's format defaults are: the rejection must not depend on them.
  $pre2 = Get-Acl -LiteralPath $guid2
  $pre2.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-20')
  Set-Acl -LiteralPath $guid2 -AclObject $pre2
  try {
    $null = Get-WorkspaceRootPolicy $vhd2 $mount2 $guid2 $serviceSid
    throw 'PREEXISTING_UNEXPECTEDLY_ACCEPTED'
  } catch {
    if ($_.Exception.Message -ne 'WORKSPACE_ROOT_OWNER_OR_DACL_UNTRUSTED') { throw ('PREEXISTING_WRONG_CODE:' + $_.Exception.Message) }
  }
  $still = Get-Acl -LiteralPath $guid2
  $stillOwner = [string]$still.Owner
  $stillSid = if ($stillOwner -match '^S-1-5-') { $stillOwner } else { ([Security.Principal.NTAccount]$stillOwner).Translate([Security.Principal.SecurityIdentifier]).Value }
  if ($stillSid -ne 'S-1-5-20') { throw ('PREEXISTING_WAS_REPAIRED:' + $stillSid) }
  $report.cases += 'PREEXISTING:REJECTED_NOT_SEIZED'

  # 6. A policy failure leaves no service/credential state behind.
  try {
    $null = Set-WorkspaceRootPolicy $vhd1 $mount1 $guid1 'bogus-sid'
    throw 'MALFORMED_SID_UNEXPECTEDLY_ACCEPTED'
  } catch {
    if ($_.Exception.Message -ne 'WORKSPACE_ROOT_SECURITY_TARGET_INVALID') { throw ('MALFORMED_WRONG_CODE:' + $_.Exception.Message) }
  }
  if ([bool](Get-Service -Name DevAIWorker -ErrorAction Ignore) -ne $svcBefore) { throw 'FAILURE_CREATED_SERVICE' }
  if ((Test-Path -LiteralPath (Join-Path $env:ProgramData 'DevAIWorker\credentials\worker.dpapi')) -ne $credBefore) { throw 'FAILURE_CREATED_CREDENTIAL' }
  $report.cases += 'FAILURE:ATOMIC_NO_SERVICE_NO_CREDENTIAL'

  Write-Output 'WORKSPACE_VOLUME_PROVISIONING_PASSED'
} finally {
  foreach ($img in @($vhd1, $vhd2)) {
    if ($img -and (Test-Path -LiteralPath $img)) {
      Dismount-DiskImage -ImagePath $img -ErrorAction SilentlyContinue | Out-Null
    }
  }
  if ((Split-Path -Parent $probeRoot) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP_PATH' }
  if (Test-Path -LiteralPath $probeRoot) { [IO.Directory]::Delete($probeRoot, $true) }
}

$report.passed = $true
Write-Output (@{cases = $report.cases; passed = $true} | ConvertTo-Json -Compress)
