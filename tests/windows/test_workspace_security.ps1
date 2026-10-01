$ErrorActionPreference='Stop'
$support=Join-Path $PSScriptRoot '../../deploy/windows/install-support.ps1'
. $support
# Exercise the real native getter/setter on an owned temporary fixture only.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-native-volume-acl-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
  $before=Get-NativeWorkspaceSecurity $temp
  $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $desired=[Security.AccessControl.RawSecurityDescriptor]::new(('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$owner+')'))
  Set-NativeWorkspaceSecurity $temp $desired
  $after=Get-NativeWorkspaceSecurity $temp
  $section=[Security.AccessControl.AccessControlSections]::Access
  if($after.GetSddlForm($section) -cne $desired.GetSddlForm($section)){throw 'NATIVE_DACL_ROUNDTRIP_FAILED'}
  if($after.Owner.Value -ne $before.Owner.Value){throw 'NATIVE_DACL_CHANGED_OWNER'}
  Set-NativeWorkspaceSecurity $temp $before
  $restored=Get-NativeWorkspaceSecurity $temp
  $beforeBytes=[byte[]]::new($before.DiscretionaryAcl.BinaryLength);$before.DiscretionaryAcl.GetBinaryForm($beforeBytes,0)
  $afterBytes=[byte[]]::new($restored.DiscretionaryAcl.BinaryLength);$restored.DiscretionaryAcl.GetBinaryForm($afterBytes,0)
  $protected=[Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
  # SetFileSecurity can clear the informational AUTO_INHERITED flag. Verify
  # actual ACE bytes (including inheritance), owner and protection, not that flag.
  if([Convert]::ToBase64String($beforeBytes) -cne [Convert]::ToBase64String($afterBytes) -or
     ($before.ControlFlags -band $protected) -ne ($restored.ControlFlags -band $protected) -or
     $restored.Owner.Value -ne $before.Owner.Value){throw 'NATIVE_DACL_ROLLBACK_FAILED'}
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
# Privileged VHDX/owner/service queries are mocked. Test target gating and policy,
# never attach, format or change a real disk or service in this test.
$script:guid='\\?\Volume{25914664-0000-0000-0000-010000000000}\'
$sid='S-1-5-80-1-2-3-4-5'
$script:writes=0;$script:volumeChecks=0
$script:descriptor=[Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
function Get-VerifiedWorkspaceVolume {param($VhdPath,$Mount,$ExpectedGuid)
  if($ExpectedGuid -cne $script:guid){throw 'WRONG_VOLUME_TARGET'}
  $script:volumeChecks++
  return @{mount_verified=$true}
}
function Get-NativeWorkspaceSecurity {param($Path)
  if($Path -cne $script:guid){throw 'WRONG_NATIVE_READ_TARGET'}
  return $script:descriptor
}
function Set-NativeWorkspaceSecurity {param($Path,$Descriptor)
  if($Path -cne $script:guid){throw 'WRONG_NATIVE_WRITE_TARGET'}
  $script:writes++
  $script:descriptor=[Security.AccessControl.RawSecurityDescriptor]::new(('O:BAG:BA'+$Descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Access)))
}
$initial=Get-WorkspaceRootPolicy 'fixed.vhdx' 'fixed-mount' $script:guid $sid
if($initial.summary.worker_can_list -or $initial.matches){throw 'MISSING_WORKER_ROOT_ACCESS_NOT_DETECTED'}
$fixed=Set-WorkspaceRootPolicy 'fixed.vhdx' 'fixed-mount' $script:guid $sid
if(!$fixed.protected -or !$fixed.worker_can_list -or !$fixed.worker_can_modify -or $fixed.foreign_allow_entries -ne 0 -or $script:writes -ne 1){throw 'PRIVATE_WORKSPACE_ROOT_POLICY_FAILED'}
Set-WorkspaceRootPolicy 'fixed.vhdx' 'fixed-mount' $script:guid $sid | Out-Null
if($script:writes -ne 1){throw 'ROOT_POLICY_NOT_IDEMPOTENT'}
try{Set-WorkspaceRootPolicy 'fixed.vhdx' 'fixed-mount' 'C:\' $sid;throw 'SYSTEM_DRIVE_ACCEPTED'}
catch{if($_.Exception.Message -ne 'WORKSPACE_ROOT_SECURITY_TARGET_INVALID'){throw}}
$script:descriptor=[Security.AccessControl.RawSecurityDescriptor]::new('O:WDG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
try{Set-WorkspaceRootPolicy 'fixed.vhdx' 'fixed-mount' $script:guid $sid;throw 'UNTRUSTED_ROOT_OWNER_ACCEPTED'}
catch{if($_.Exception.Message -ne 'WORKSPACE_ROOT_OWNER_OR_DACL_UNTRUSTED'){throw}}
$script:descriptor=[Security.AccessControl.RawSecurityDescriptor]::new(('O:BAG:BAD:P(D;;FA;;;'+$sid+')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'))
try{Set-WorkspaceRootPolicy 'fixed.vhdx' 'fixed-mount' $script:guid $sid;throw 'DENY_POLICY_OVERRIDDEN'}
catch{if($_.Exception.Message -ne 'WORKSPACE_ROOT_DENY_REQUIRES_REVIEW'){throw}}
if($script:writes -ne 1){throw 'UNVERIFIED_ROOT_MUTATED'}
Write-Output 'WORKSPACE_ROOT_SECURITY_TEST_PASSED'
