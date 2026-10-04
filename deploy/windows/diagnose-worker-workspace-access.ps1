param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][string]$ExpectedManifestSHA256,
  [Parameter(Mandatory=$true)][string]$ExpectedInstallerSHA256,
  [switch]$IncludeDeviceSecurity
)
$ErrorActionPreference='Stop'

function Initialize-WorkspaceAccessReader {
  if ('DevAIWorkspaceAccessReader' -as [type]) {return}
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class DevAIWorkspaceAccessReader {
  [StructLayout(LayoutKind.Sequential)] public struct AttributeTag {
    public uint Attributes; public uint Tag;
  }
  public sealed class Result {
    public int Error; public int SecurityError; public int TagError;
    public uint Attributes; public uint Tag; public byte[] Descriptor;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  private static extern SafeFileHandle CreateFileW(string name,uint access,uint share,
    IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int kind,
    out AttributeTag info,uint size);
  [DllImport("advapi32.dll")]
  private static extern uint GetSecurityInfo(SafeFileHandle handle,int kind,uint info,
    IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")]
  private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")]
  private static extern IntPtr LocalFree(IntPtr pointer);
  public static Result Read(string path,bool noFollow) {
    return Read(path,noFollow,false);
  }
  public static Result Read(string path,bool noFollow,bool device) {
    Result result=new Result();
    // Directory/file mode: READ_CONTROL + FILE_READ_ATTRIBUTES. Device mode:
    // READ_CONTROL ONLY. Never request data read/write, IOCTLs, backup privileges
    // or inheritance. OPEN_EXISTING; device paths are fixed by verified inventory.
    using(SafeFileHandle handle=CreateFileW(path,device ? 0x20000u : 0x20080u,
      device ? 3u : 7u,IntPtr.Zero,3,
      device ? 0u : (0x02000000u | (noFollow ? 0x00200000u : 0)),IntPtr.Zero)) {
      if(handle.IsInvalid) {result.Error=Marshal.GetLastWin32Error();return result;}
      AttributeTag attributes;
      if(!device && GetFileInformationByHandleEx(handle,9,out attributes,8)) {
        result.Attributes=attributes.Attributes;result.Tag=attributes.Tag;
      } else if(!device) {result.TagError=Marshal.GetLastWin32Error();}
      IntPtr descriptor=IntPtr.Zero;
      result.SecurityError=(int)GetSecurityInfo(handle,1,5,
        IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out descriptor);
      try {
        if(result.SecurityError==0 && descriptor!=IntPtr.Zero) {
          uint size=GetSecurityDescriptorLength(descriptor);
          if(size==0 || size>65536) {result.SecurityError=1338;return result;}
          result.Descriptor=new byte[size];
          Marshal.Copy(descriptor,result.Descriptor,0,(int)size);
        }
      } finally {if(descriptor!=IntPtr.Zero) {LocalFree(descriptor);}}
    }
    return result;
  }
}
'@
}

function Get-WorkspaceAccessSummary([string]$Label,$Result,[string]$ServiceSid) {
  $allowedLabels=@('state_parent','state_root','mount_host_entry','mount_target','guid_root','vhd_image','volume_device','disk_device')
  if($Label -cnotin $allowedLabels){throw 'ACCESS_DIAGNOSTIC_LABEL_INVALID'}
  $summary=@{label=$Label;opened_as_admin=($Result.Error -eq 0);open_winerror=[int]$Result.Error;
    security_winerror=[int]$Result.SecurityError;tag_winerror=[int]$Result.TagError;
    is_directory=[bool]($Result.Attributes -band 0x10);
    is_mount_point=($Result.Tag -eq 0xa0000003L);acl_readable=$false}
  if(!$Result.Descriptor -or $Result.SecurityError -ne 0){return $summary}
  $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$Result.Descriptor,0)
  $summary.acl_readable=$true
  $summary.owner_trusted=($descriptor.Owner.Value -in @('S-1-5-18','S-1-5-32-544'))
  $summary.protected=[bool]($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
  $summary.null_dacl=($null -eq $descriptor.DiscretionaryAcl)
  $allow=0;$deny=0;$foreign=0;$unknown=0;$inheritOnly=0
  $common=@{'S-1-1-0'='everyone';'S-1-5-11'='authenticated_users';'S-1-5-32-545'='users';'S-1-15-2-1'='appcontainers'}
  foreach($labelName in $common.Values){$summary[$labelName+'_allow_present']=$false}
  foreach($ace in $descriptor.DiscretionaryAcl) {
    if($ace -isnot [Security.AccessControl.CommonAce]){$unknown++;continue}
    if(([int]$ace.AceFlags -band [int][Security.AccessControl.AceFlags]::InheritOnly) -ne 0){$inheritOnly++;continue}
    $sid=$ace.SecurityIdentifier.Value
    if($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed) {
      if($common.ContainsKey($sid)){$summary[$common[$sid]+'_allow_present']=$true}
      if($sid -notin @('S-1-5-18','S-1-5-32-544',$ServiceSid)){$foreign++}
      if($sid -ceq $ServiceSid){$allow=$allow -bor $ace.AccessMask}
    } elseif($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessDenied) {
      # Groups may also deny the actual token; report presence, not effective access.
      $deny++
    } else {$unknown++}
  }
  $summary.worker_explicit_allow_list=[bool]($allow -band 1)
  $summary.worker_explicit_allow_traverse=[bool]($allow -band 0x20)
  $summary.worker_explicit_allow_read_control=[bool]($allow -band 0x20000)
  $summary.worker_explicit_allow_modify=(($allow -band 0x1301bf) -eq 0x1301bf)
  # Generic bits are reported separately; they must not be mistaken for the
  # mapped filesystem bit mask on a device. No claim of effective token access.
  $summary.worker_generic_read=[bool]($allow -band [int]::MinValue)
  $summary.worker_generic_write=[bool]($allow -band 0x40000000)
  $summary.worker_full_control=(($allow -band 0x1f01ff) -eq 0x1f01ff -or ($allow -band 0x10000000) -ne 0)
  $summary.deny_entries=$deny;$summary.foreign_allow_entries=$foreign
  $summary.other_ace_entries=$unknown;$summary.inherit_only_entries=$inheritOnly
  return $summary
}

try {
  if((Get-FileHash -LiteralPath (Join-Path $PackageRoot 'manifest.json')).Hash.ToLowerInvariant() -cne $ExpectedManifestSHA256){throw 'PACKAGE_MANIFEST_CHANGED'}
  $installer=Join-Path $PackageRoot 'install-worker.ps1'
  if((Get-FileHash -LiteralPath $installer).Hash.ToLowerInvariant() -cne $ExpectedInstallerSHA256){throw 'PACKAGE_INSTALLER_CHANGED'}
  & $installer -PackageRoot $PackageRoot -ValidateOnly
  $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ADMINISTRATOR_DIAGNOSTIC_REQUIRED'}
  $code=Join-Path $env:ProgramFiles 'DevAIWorker'
  $state=Join-Path $env:ProgramData 'DevAIWorker'
  . (Join-Path $PackageRoot 'install-support.ps1')
  # Immutable release identity. The external caller-supplied digest above
  # authenticates manifest.json; everything below is verified payload.
  $releaseManifest=Read-ReleaseManifest $PackageRoot
  Assert-ManifestPayload $PackageRoot $releaseManifest | Out-Null
  Assert-ManifestIdentityAggregate $PackageRoot $releaseManifest | Out-Null
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
  if($errors.Count){throw 'INSTALLER_SYNTAX_INVALID'}
  $entry=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
  if(!$entry){throw 'PACKAGE_PATH_VALIDATOR_MISSING'}
  . ([ScriptBlock]::Create($entry.Extent.Text))
  # No old hashes: the complete installed inventory must match THIS package.
  $verified=Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $releaseManifest.files.'control/worker_agent/windows_service.py'
  $mount=Join-Path $state 'workspace-volume'
  $policy=Get-WorkspaceRootPolicy (Join-Path $state 'volumes/workspace.vhdx') $mount $verified.config.volume_guid $verified.config.service_sid
  Initialize-WorkspaceAccessReader
  $report=@{read_only=$true;at=[DateTime]::UtcNow.ToString('o');installed_runtime_validated=$true;
    volume=$verified.volume;root_policy_matches=[bool]$policy.matches;
    access_context='ADMINISTRATOR_METADATA_ONLY';effective_service_access='NOT_TESTED';access=@()}
  $targets=@(
    @{label='state_parent';path=[IO.Path]::GetDirectoryName($state);no_follow=$true},
    @{label='state_root';path=$state;no_follow=$true},
    @{label='mount_host_entry';path=$mount;no_follow=$true},
    @{label='mount_target';path=$mount;no_follow=$false},
    @{label='guid_root';path=$verified.config.volume_guid;no_follow=$false}
  )
  foreach($target in $targets) {
    $result=[DevAIWorkspaceAccessReader]::Read($target.path,$target.no_follow)
    $report.access+=Get-WorkspaceAccessSummary $target.label $result $verified.config.service_sid
  }
  if($IncludeDeviceSecurity) {
    # Security metadata ONLY on the exact, already verified private VHD. Never
    # accept a disk/volume argument and never request raw read/write or IOCTLs.
    $disk=Get-VerifiedVhdDisk (Join-Path $state 'volumes/workspace.vhdx')
    if($disk.Number -lt 0 -or $disk.Number -gt 1024){throw 'VERIFIED_DISK_NUMBER_INVALID'}
    $deviceTargets=@(
      @{label='volume_device';path=$verified.config.volume_guid.TrimEnd([char]'\')},
      @{label='disk_device';path=('\\.\PhysicalDrive'+[int]$disk.Number)}
    )
    $imageMetadata=[DevAIWorkspaceAccessReader]::Read((Join-Path $state 'volumes/workspace.vhdx'),$true)
    $report.access+=Get-WorkspaceAccessSummary 'vhd_image' $imageMetadata $verified.config.service_sid
    foreach($target in $deviceTargets) {
      $result=[DevAIWorkspaceAccessReader]::Read($target.path,$false,$true)
      $report.access+=Get-WorkspaceAccessSummary $target.label $result $verified.config.service_sid
    }
    $report.device_security_metadata_only=$true
    $report.attachment_filter_verified=$false
  }
  $serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\DevAIWorker'
  $settings=Get-ItemProperty -LiteralPath $serviceKey
  $report.service_sid_type=[int]$settings.ServiceSidType
  $privileges=@($settings.RequiredPrivileges)
  $report.required_privileges_configured=($null -ne $settings.PSObject.Properties['RequiredPrivileges'])
  $report.change_notify_configured=[bool]($privileges -contains 'SeChangeNotifyPrivilege')
  $report.worker_state=(Get-Service -Name DevAIWorker).Status.ToString()
  $report.volume_host_state=(Get-Service -Name DevAIWorkerVolumes).Status.ToString()
  Write-Output ($report | ConvertTo-Json -Depth 6 -Compress)
} catch {
  # No raw errors, paths, file contents, exception messages or config values.
  $known=@('PACKAGE_MANIFEST_CHANGED','PACKAGE_INSTALLER_CHANGED','ADMINISTRATOR_DIAGNOSTIC_REQUIRED',
    'INSTALLER_SYNTAX_INVALID','PACKAGE_PATH_VALIDATOR_MISSING','ACCESS_DIAGNOSTIC_LABEL_INVALID')
  $safe='DIAGNOSTIC_VALIDATION_OR_METADATA_FAILED'
  if($_.Exception.Message -cin $known){$safe=$_.Exception.Message}
  Write-Output (@{read_only=$true;completed=$false;code=$safe} | ConvertTo-Json -Compress)
  throw $safe
}
