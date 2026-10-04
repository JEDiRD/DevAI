# RH-B 5A-2B: REAL ACL coverage for the target personal-denial fixture.
#
# This harness deliberately does NOT mock Get-Acl. It creates a genuine fixture
# on a real NTFS volume through the REAL production helper, then inspects the
# resulting security descriptor structurally:
#
#   * DACL protection state
#   * exact ACE count
#   * exact principal SID set
#   * rights and inheritance flags per ACE
#   * absence of any service SID ACE
#   * absence of broad principals (Everyone / Users / Authenticated Users)
#
# It asserts the RECOVERED historical model:
#   D:P (A;OICI;FA;;;SY) (A;OICI;FA;;;BA) (A;OICI;FA;;;<owner>)
#
# It does NOT assert the runtime property (service identity read -> PermissionError
# -> service_personal_profile_denied). That requires the elevated native gate and
# is reported separately as blocked.
$ErrorActionPreference='Stop'
$support=Join-Path $PSScriptRoot '../../deploy/windows/install-support.ps1'
. $support

$ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$profileRoot=Join-Path $env:USERPROFILE ('rhb-acl-probe-'+[Guid]::NewGuid().ToString('N'))

try {
  # A service-shaped SID proves the fixture grants the worker identity nothing.
  $serviceSid='S-1-5-80-1-2-3-4-5'
  $broadSids=@(
    'S-1-1-0',      # Everyone
    'S-1-5-32-545', # BUILTIN\Users
    'S-1-5-11',     # NT AUTHORITY\Authenticated Users
    'S-1-5-32-546', # BUILTIN\Guests
    'S-1-5-32-544'  # handled separately: Administrators is INTENDED
  )

  $fixture=New-TargetPersonalDenialFixture -ProfileRoot $profileRoot -OwnerSid $ownerSid

  if (![IO.Path]::IsPathRooted($fixture)) { throw 'FIXTURE_NOT_ABSOLUTE' }
  if (-not $fixture.StartsWith($profileRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'FIXTURE_OUTSIDE_PROFILE_ROOT' }

  # Non-reparse, on the fixture and on every parent up to the root.
  foreach ($path in @($fixture,(Split-Path -Parent $fixture),$profileRoot)) {
    $item=Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'FIXTURE_REPARSE_POINT' }
  }

  # ---- Structural ACL assertions on the REAL descriptor -------------------
  $expected=@('S-1-5-18','S-1-5-32-544',$ownerSid)
  foreach ($path in @($fixture,(Split-Path -Parent $fixture))) {
    $acl=Get-Acl -LiteralPath $path
    $label=(Split-Path -Leaf $path)

    if (!$acl.AreAccessRulesProtected) { throw "DACL_NOT_PROTECTED:$label" }

    $allow=@($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' })
    if ($allow.Count -ne 3) { throw "ACE_COUNT_NOT_THREE:$label=$($allow.Count)" }
    if (@($acl.Access | Where-Object { $_.AccessControlType -ne 'Allow' }).Count -ne 0) { throw "NON_ALLOW_ACE_PRESENT:$label" }

    $actual=@($allow | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    if (($actual -join ',') -cne ((@($expected) | Sort-Object -Unique) -join ',')) { throw "PRINCIPAL_SET_MISMATCH:$label=$($actual -join ',')" }

    foreach ($rule in $allow) {
      $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw "FULL_CONTROL_MISSING:$label=$sid"
      }
      # The directory ACEs must be inheritable (OICI equivalent).
      if ($path -eq (Split-Path -Parent $fixture)) {
        $need=@([Security.AccessControl.InheritanceFlags]::ContainerInherit,[Security.AccessControl.InheritanceFlags]::ObjectInherit)
        foreach ($flag in $need) {
          if (($rule.InheritanceFlags -band $flag) -ne $flag) { throw "INHERITANCE_MISSING:$label=$sid=$flag" }
        }
      }
      if ($sid -match '^S-1-5-80(-\d+){5}$') { throw "SERVICE_SID_ACE_PRESENT:$label=$sid" }
      foreach ($broad in $broadSids) {
        if ($sid -eq $broad -and $sid -ne 'S-1-5-32-544') { throw "BROAD_PRINCIPAL_ACE_PRESENT:$label=$sid" }
      }
    }
  }

  # The production validator must independently agree, including the explicit
  # "no service identity read" check.
  if (!(Assert-TargetPersonalDenialFixture -Fixture $fixture -OwnerSid $ownerSid -ServiceSid $serviceSid)) {
    throw 'PRODUCTION_VALIDATOR_DISAGREED'
  }

  # ---- Negative: a REPARSE fixture must be rejected ----------------------
  $reparseParent=Join-Path $profileRoot 'reparse-parent'
  [IO.Directory]::CreateDirectory($reparseParent) | Out-Null
  $reparseTarget=Join-Path $profileRoot 'reparse-target'
  [IO.Directory]::CreateDirectory($reparseTarget) | Out-Null
  $junction=Join-Path $reparseParent 'junction'
  New-Item -ItemType Junction -Path $junction -Target $reparseTarget | Out-Null
  try {
    $throughReparse=Join-Path $junction 'service-access-denial.fixture'
    [IO.File]::WriteAllText($throughReparse,'non-secret fixture')
    $rejected=$false
    try { Assert-TargetPersonalDenialFixture -Fixture $throughReparse -OwnerSid $ownerSid } catch { $rejected=$true }
    if (!$rejected) { throw 'REPARSE_PARENT_ACCEPTED' }

    $junctionItself=Join-Path $junction 'x'
    if (Join-Path $reparseParent 'junction') { }
    $rejectedSelf=$false
    try { Assert-ManagedNoReparse $junction | Out-Null } catch { $rejectedSelf=$true }
    if (!$rejectedSelf) { throw 'REPARSE_SELF_ACCEPTED' }
  } finally {
    if ([IO.Path]::GetDirectoryName($junction) -ne $reparseParent) { throw 'UNSAFE_JUNCTION_CLEANUP' }
    [IO.Directory]::Delete($junction,$false)
  }

  # ---- Negative: forbidden / shared locations ----------------------------
  foreach ($forbidden in @($env:ProgramData,$env:ProgramFiles,[IO.Path]::GetTempPath())) {
    if ([string]::IsNullOrWhiteSpace($forbidden)) { continue }
    $candidate=Join-Path $forbidden ('rhb-probe-'+[Guid]::NewGuid().ToString('N')+'.fixture')
    $rejected=$false
    try { Assert-TargetPersonalDenialFixture -Fixture $candidate -OwnerSid $ownerSid } catch { $rejected=$true }
    if (!$rejected) { throw "FORBIDDEN_LOCATION_ACCEPTED:$forbidden" }
  }

  Write-Output (@{
    acl_harness='REAL_NTFS'
    dacl_protected=$true
    ace_count=$allow.Count
    principals=(@($actual) | Sort-Object -Unique)
    service_sid_ace_present=$false
    broad_principal_ace_present=$false
    reparse_fixture_rejected=$true
    reparse_parent_rejected=$true
    forbidden_location_rejected=$true
    runtime_denial_gate='BLOCKED_PENDING_ELEVATED_EXECUTION'
    passed=$true
  } | ConvertTo-Json -Compress)
} finally {
  if ($profileRoot.StartsWith($env:USERPROFILE,[StringComparison]::OrdinalIgnoreCase) -and
      $profileRoot -ne $env:USERPROFILE -and (Test-Path -LiteralPath $profileRoot)) {
    [IO.Directory]::Delete($profileRoot,$true)
  }
}