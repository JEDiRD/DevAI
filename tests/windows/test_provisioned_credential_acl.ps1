param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'))
$ErrorActionPreference = 'Stop'

# RH-D: the installer provisioned worker.dpapi through the provision child and
# created the Windows services without ever stamping the managed ACL on the
# credential file. The provision child leaves an inherited (unprotected) DACL,
# but the worker service verify_install gate requires a protected DACL on
# every state path, so the first boot died in install_verification with
# SERVICE_ACL_UNSAFE and Start-Service DevAIWorkerVolumes failed. The
# installer now stamps the service.json model on the freshly provisioned
# credential and asserts the stamp before any service is created.
#
# This harness executes the REAL Set-ManagedAcl (extracted from the installer
# body by AST, never a forked copy) and the REAL Assert-ManagedPrivateAcl
# from install-support, and proves: the unstamped state fails the managed
# assertion (negative control -- the assert would have caught the defect),
# the stamp meets the model (positive), the service's protected-DACL check
# passes on the stamped file, and the installer orders stamp+assert after
# provisioning and before service creation. Stamping another identity's owner
# requires elevation; without it this harness reports the standard blocked
# marker (exit 0, no JSON verdict) instead of failing; canonical STEP7 runs
# it elevated.
$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
. (Join-Path $DeployRoot 'install-support.ps1')

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Output 'BLOCKED_PENDING_ELEVATED_EXECUTION:credential ACL stamping requires elevation'
  exit 0
}

# Real installer function, extracted from the installer body the same way
# test_installer.ps1 extracts Assert-PackageEntryName: no forked copy.
$installerPath = Join-Path $DeployRoot 'install-worker.ps1'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'INSTALLER_SYNTAX_INVALID' }
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-ManagedAcl' }, $true)
if ($null -eq $function) { throw 'SET_MANAGED_ACL_NOT_FOUND_IN_INSTALLER' }
. ([ScriptBlock]::Create($function.Extent.Text))

# Shape-valid witness SID. Policy functions validate the SHAPE only; no real
# service is created, read or required by any assertion below.
$serviceSid = 'S-1-5-80-1-2-3-4-5'
$report = [ordered]@{ cases = @(); passed = $false }

$probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('rhb-credacl-probe-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($probeRoot) | Out-Null
try {
  # 1. Negative control: a freshly provisioned credential (inherited,
  # unprotected DACL, exactly what the provision child leaves) FAILS the
  # managed assertion. This is what the service gate rejected at first boot.
  $cred = Join-Path $probeRoot 'worker.dpapi'
  [IO.File]::WriteAllText($cred, 'provision-child-state')
  $aclBefore = Get-Acl -LiteralPath $cred
  if ($aclBefore.AreAccessRulesProtected) { throw 'PROBE_FILE_UNEXPECTEDLY_PROTECTED' }
  try { Assert-ManagedPrivateAcl $cred $serviceSid; throw 'UNSTAMPED_CREDENTIAL_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'MANAGED_INSTALL_ACL_UNSAFE') { throw } }
  $report.cases += 'NEGATIVE:UNSTAMPED_CREDENTIAL_FAILS_MANAGED_ASSERT'

  # 2. The installer stamp (exact service.json model: file, service Read)
  # meets the managed assertion.
  Set-ManagedAcl $cred $serviceSid 'Read' $false
  Assert-ManagedPrivateAcl $cred $serviceSid
  $report.cases += 'STAMP:SET_MANAGED_ACL_MEETS_MANAGED_ASSERT'

  # 3. The service's own protected-DACL check (verify_install exit 12) passes
  # on the stamped file, with the owner still in the allowed set.
  $aclAfter = Get-Acl -LiteralPath $cred
  if (-not $aclAfter.AreAccessRulesProtected) { throw 'STAMPED_FILE_NOT_PROTECTED' }
  $ownerAfter = ([Security.Principal.NTAccount]$aclAfter.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
  if ($ownerAfter -notin @('S-1-5-18', 'S-1-5-32-544')) { throw ('STAMPED_OWNER_UNEXPECTED:' + $ownerAfter) }
  foreach ($entry in $aclAfter.Access) {
    $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18', 'S-1-5-32-544', $serviceSid)) {
      throw ('STAMPED_FOREIGN_ACE:' + $sid)
    }
  }
  $report.cases += 'VERIFY_MODEL:PROTECTED_OWNER_AND_ALLOW_LIST'

  # 4. Installer ordering: stamp + assert after provisioning, before any
  # service creation or start.
  $installerSource = [IO.File]::ReadAllText($installerPath)
  # Anchored after provisioning: an earlier Assert-ManagedPrivateAcl covers
  # the preserved-credential branch, which must not satisfy this gate.
  $provisionSite = $installerSource.IndexOf('Invoke-TargetCredentialProvisioning -InstallRoot')
  $stampSite = $installerSource.IndexOf('Set-ManagedAcl $credential $serviceSid', $provisionSite)
  $assertSite = $installerSource.IndexOf('Assert-ManagedPrivateAcl $credential $serviceSid', $stampSite)
  $serviceSite = $installerSource.IndexOf('New-Service -Name DevAIWorkerVolumes')
  foreach ($site in @($provisionSite, $stampSite, $assertSite, $serviceSite)) {
    if ($site -lt 0) { throw 'CREDENTIAL_STAMP_ORDERING_SITE_MISSING' }
  }
  if (-not ($provisionSite -lt $stampSite -and $stampSite -lt $assertSite -and $assertSite -lt $serviceSite)) {
    throw 'CREDENTIAL_STAMP_ORDERING_WRONG'
  }
  $report.cases += 'ORDER:STAMP_AND_ASSERT_AFTER_PROVISION_BEFORE_SERVICE'

  $report.passed = $true
}
finally {
  Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'PROVISIONED_CREDENTIAL_ACL_CASES_PASSED'
Write-Output ($report | ConvertTo-Json -Depth 4 -Compress)
