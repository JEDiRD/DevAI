# Definitions only. The installer loads this manifested file AFTER validation.
function Assert-ManagedNoReparse([string]$Path) {
  $item=Get-Item -LiteralPath $Path -Force
  for ($ancestor=$item; $null -ne $ancestor; $ancestor=$(if ($ancestor.PSIsContainer) {$ancestor.Parent} else {$ancestor.Directory})) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'MANAGED_INSTALL_REPARSE_POINT' }
  }
  return $item
}

function Assert-ManagedPrivateAcl([string]$Path,[string]$ServiceSid,[switch]$AllowInherited) {
  Assert-ManagedNoReparse $Path | Out-Null
  $acl=Get-Acl -LiteralPath $Path
  $owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin @('S-1-5-18','S-1-5-32-544') -or (!$AllowInherited -and !$acl.AreAccessRulesProtected)) { throw 'MANAGED_INSTALL_ACL_UNSAFE' }
  foreach ($entry in $acl.Access) {
    $sid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -eq 'Allow') {
      if ($sid -notin @('S-1-5-18','S-1-5-32-544',$ServiceSid)) { throw 'MANAGED_INSTALL_ACL_UNSAFE' }
      if ($sid -eq $ServiceSid -and ([int]$entry.FileSystemRights -band 0x000d0116)) { throw 'MANAGED_INSTALL_ACL_UNSAFE' }
    }
  }
}

function Get-WorkerServiceCommand([string]$InstallRoot,[string]$ConfigFile) {
  $python=Join-Path $InstallRoot 'host-runtime/python.exe'
  return ('"'+$python+'" -I -S -B -m worker_agent.windows_service --config "'+$ConfigFile+'"')
}

function New-WorkerService([string]$BinaryPath) {
  # CIM passes a string to SCM, bypassing Windows PowerShell's native argv
  # quoting. A virtual account has no operator password or secret argument.
  $arguments=@{Name='DevAIWorker';DisplayName='DevAI isolated Windows Worker';PathName=$BinaryPath;
    ServiceType=[byte]16;ErrorControl=[byte]1;StartMode='Automatic';DesktopInteract=$false;
    StartName='NT SERVICE\DevAIWorker';StartPassword=$null;ServiceDependencies=[string[]]@('DevAIWorkerVolumes')}
  $created=Invoke-CimMethod -Namespace root/cimv2 -ClassName Win32_Service -MethodName Create -Arguments $arguments
  if ($created.ReturnValue -ne 0) { throw ('WORKER_SERVICE_CREATION_FAILED_'+[uint32]$created.ReturnValue) }
  & sc.exe config DevAIWorker start= delayed-auto | Out-Null
  if ($LASTEXITCODE -ne 0) { throw ('SERVICE_DELAYED_START_FAILED_'+$LASTEXITCODE) }
  $actual=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
  if ($actual.PathName -cne $BinaryPath -or $actual.StartName -ne 'NT SERVICE\DevAIWorker' -or $actual.StartMode -ne 'Auto') { throw 'SERVICE_IDENTITY_OR_PATH_NOT_VERIFIED' }
}

function Set-WorkerServiceRecovery {
  foreach ($name in @('DevAIWorkerVolumes','DevAIWorker')) {
    & sc.exe failure $name reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('SERVICE_RECOVERY_CONFIG_FAILED_'+$LASTEXITCODE) }
    & sc.exe failureflag $name 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('SERVICE_FAILURE_FLAG_FAILED_'+$LASTEXITCODE) }
  }
  & sc.exe sidtype DevAIWorker unrestricted | Out-Null
  if ($LASTEXITCODE -ne 0) { throw ('SERVICE_SID_CONFIG_FAILED_'+$LASTEXITCODE) }
}

function Get-VerifiedVhdDisk([string]$VhdPath) {
  $image=Get-DiskImage -ImagePath $VhdPath
  if (!$image.Attached -or ![string]::Equals($image.ImagePath,$VhdPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'WORKSPACE_IMAGE_IDENTITY_MISMATCH' }
  $disks=@($image | Get-Disk)
  if ($disks.Count -ne 1) { throw 'WORKSPACE_DISK_IDENTITY_MISMATCH' }
  $disk=$disks[0]
  if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne 134217728 -or
      ([string]$disk.BusType).Replace(' ','') -ne 'FileBackedVirtual' -or
      ![string]::Equals($disk.Location,$VhdPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'WORKSPACE_DISK_IDENTITY_MISMATCH' }
  return $disk
}

function Get-WorkspaceMountGuid([string]$Mount) {
  if (!('DevAIVolume' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class DevAIVolume {
 [DllImport("kernel32.dll",EntryPoint="GetVolumeNameForVolumeMountPointW",CharSet=CharSet.Unicode,SetLastError=true)]
 public static extern bool GetVolumeNameForVolumeMountPoint(string path,StringBuilder name,uint size);
}
'@
  }
  $guid=[Text.StringBuilder]::new(1024)
  if (![DevAIVolume]::GetVolumeNameForVolumeMountPoint($Mount+'\',$guid,1024)) { throw 'WORKSPACE_MOUNT_NOT_VERIFIED' }
  return $guid.ToString()
}

function Get-VerifiedWorkspaceVolume([string]$VhdPath,[string]$Mount,[string]$ExpectedGuid) {
  $disk=Get-VerifiedVhdDisk $VhdPath
  $all=@(Get-Partition -DiskNumber $disk.Number)
  $reserved=@($all | Where-Object {$_.Type -eq 'Reserved'})
  if ($reserved.Count -gt 1 -or @($reserved | Where-Object {$_.Size -gt 16777216}).Count) { throw 'WORKSPACE_PARTITION_MISMATCH' }
  $partitions=@($all | Where-Object {$_.Type -ne 'Reserved'})
  if ($partitions.Count -ne 1) { throw 'WORKSPACE_PARTITION_MISMATCH' }
  $partition=$partitions[0]
  if ([int][char]$partition.DriveLetter -ne 0) { throw 'WORKSPACE_UNEXPECTED_DRIVE_LETTER' }
  $volumes=@($partition | Get-Volume)
  if ($volumes.Count -ne 1 -or $volumes[0].FileSystemType -ne 'NTFS' -or
      $volumes[0].FileSystemLabel -ne 'DevAIWorkspace' -or $volumes[0].HealthStatus -ne 'Healthy' -or
      $volumes[0].Size -le 0 -or $volumes[0].Size -gt 134217728) { throw 'WORKSPACE_FILESYSTEM_NOT_VERIFIED' }
  if ((Get-WorkspaceMountGuid $Mount) -cne $ExpectedGuid) { throw 'WORKSPACE_VOLUME_MISMATCH' }
  $allowed=@(($Mount.TrimEnd('\')+'\'),$ExpectedGuid)
  if (@($partition.AccessPaths | Where-Object {$_ -notin $allowed}).Count -or
      $allowed[0] -notin $partition.AccessPaths -or $ExpectedGuid -notin $partition.AccessPaths) { throw 'WORKSPACE_ACCESS_PATH_MISMATCH' }
  return @{disk_number=[uint32]$disk.Number;file_backed=$true;disk_bytes=134217728;filesystem='NTFS';no_drive_letter=$true;mount_verified=$true}
}

function Assert-PartialWorkerInstall([string]$InstallRoot,[string]$StateRoot,$Package,[switch]$ExistingService,[string]$PreviousServiceHash,[string]$PreviousWorkspaceHash) {
  if (!$ExistingService -and (Get-Service -Name DevAIWorker -ErrorAction Ignore)) { throw 'RESUME_REQUIRES_WORKER_SERVICE_ABSENT' }
  if ($ExistingService -and $PreviousServiceHash -notmatch '^[a-f0-9]{64}$') { throw 'DIAGNOSTIC_PREVIOUS_HASH_REQUIRED' }
  if ($PreviousWorkspaceHash -and (!$ExistingService -or $PreviousWorkspaceHash -notmatch '^[a-f0-9]{64}$')) { throw 'WORKSPACE_PREVIOUS_HASH_INVALID' }
  Assert-ManagedNoReparse $InstallRoot | Out-Null
  Assert-ManagedNoReparse $StateRoot | Out-Null
  $sidOutput=& sc.exe showsid DevAIWorker
  $serviceSid=([regex]::Match(($sidOutput -join ' '),'S-1-5-80(?:-\d+){5}')).Value
  if (!$serviceSid) { throw 'SERVICE_SID_UNAVAILABLE' }
  $configFile=Join-Path $StateRoot 'service.json'
  $manifestFile=Join-Path $InstallRoot 'manifest.json'
  $vhd=Join-Path $StateRoot 'volumes/workspace.vhdx'
  foreach ($path in @($InstallRoot,$StateRoot,$configFile,(Join-Path $StateRoot 'credentials'),
      (Join-Path $StateRoot 'credentials/worker.dpapi'),(Join-Path $StateRoot 'volumes'),$vhd,(Join-Path $StateRoot 'volumes/attach.txt'))) {
    Assert-ManagedPrivateAcl $path $serviceSid
  }
  # The original installer inherited this file's safe DACL from the protected
  # code root. Accept that exact legacy state, still checking owner and rights.
  Assert-ManagedPrivateAcl $manifestFile $serviceSid -AllowInherited
  # This config contains paths, IDs and hashes only. Never read/decrypt tokens.
  $config=Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
  $keys=@('worker_id','api_base_url','heartbeat_seconds','poll_seconds','credential_path','service_sid','volume_guid','sandbox_runtime','sandbox_executable_sha256','sandbox_payload_sha256','personal_denial_fixture')
  if (@($config.PSObject.Properties.Name | Where-Object {$_ -notin $keys}).Count -or
      $config.worker_id -ne $Package.worker_id -or $config.api_base_url -ne $Package.api_base_url -or
      $config.service_sid -ne $serviceSid -or $config.personal_denial_fixture -ne $Package.personal_denial_fixture -or
      $config.credential_path -ne (Join-Path $StateRoot 'credentials/worker.dpapi') -or
      $config.sandbox_runtime -ne (Join-Path $InstallRoot 'sandbox-runtime')) { throw 'PARTIAL_INSTALL_CONFIG_MISMATCH' }
  $base=Get-WorkerServiceCommand $InstallRoot $configFile
  if ($ExistingService) {
    $worker=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
    if (!$worker -or $worker.StartName -ne 'NT SERVICE\DevAIWorker' -or $worker.PathName -cne $base -or
        $worker.StartMode -ne 'Auto' -or $worker.State -notin @('Stopped','Running')) { throw 'DIAGNOSTIC_WORKER_SERVICE_MISMATCH' }
  }
  $helper=Get-CimInstance Win32_Service -Filter "Name='DevAIWorkerVolumes'"
  $helperStates=if ($ExistingService) {@('Stopped','Running')} else {@('Stopped')}
  if (!$helper -or $helper.State -notin $helperStates -or $helper.StartName -ne 'LocalSystem' -or
      $helper.PathName -cne ($base+' --volume-host')) { throw 'PARTIAL_INSTALL_HELPER_MISMATCH' }
  $manifest=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
  $verified=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in $manifest.PSObject.Properties) {
    Assert-PackageEntryName $entry.Name
    $path=[IO.Path]::GetFullPath((Join-Path $InstallRoot $entry.Name))
    if (!$path.StartsWith($InstallRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or !$verified.Add($path)) { throw 'INSTALLED_MANIFEST_PATH_INVALID' }
    Assert-ManagedNoReparse $path | Out-Null
    if ($entry.Value -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'INSTALLED_RUNTIME_INTEGRITY_FAILED' }
    $packaged=$Package.files.PSObject.Properties[$entry.Name]
    if ($ExistingService) {
      $allowed=if ($entry.Name -eq 'control/worker_agent/windows_service.py') {@($PreviousServiceHash,$packaged.Value)}
        elseif ($entry.Name -eq 'control/worker_agent/workspace.py' -and $PreviousWorkspaceHash) {@($PreviousWorkspaceHash,$packaged.Value)} else {@($packaged.Value)}
      if (!$packaged -or $entry.Value -notin $allowed) { throw 'DIAGNOSTIC_PACKAGE_RUNTIME_MISMATCH' }
    } elseif (!$packaged -or ($entry.Name -ne 'control/worker_agent/volume_host.py' -and $entry.Value -ne $packaged.Value)) { throw 'RESUME_PACKAGE_RUNTIME_MISMATCH' }
  }
  $directories=[Collections.Generic.Stack[string]]::new()
  $directories.Push($InstallRoot)
  while ($directories.Count) {
    foreach ($file in Get-ChildItem -LiteralPath $directories.Pop() -Force) {
      if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'MANAGED_INSTALL_REPARSE_POINT' }
      if ($file.PSIsContainer) {$directories.Push($file.FullName)}
      elseif ($file.FullName -ne $manifestFile -and !$verified.Contains($file.FullName)) { throw 'INSTALLED_RUNTIME_UNMANIFESTED_FILE' }
    }
  }
  foreach ($required in @('host-runtime/python.exe','sandbox-runtime/python.exe','sandbox-runtime/synthetic_process.py','control/worker_agent/windows_service.py','control/worker_agent/volume_host.py')) {
    if (!$verified.Contains([IO.Path]::GetFullPath((Join-Path $InstallRoot $required)))) { throw 'INSTALLED_RUNTIME_REQUIRED_FILE_MISSING' }
  }
  if ($config.sandbox_executable_sha256 -ne $manifest.'sandbox-runtime/python.exe' -or
      $config.sandbox_payload_sha256 -ne $manifest.'sandbox-runtime/synthetic_process.py') { throw 'PARTIAL_INSTALL_ALLOWLIST_MISMATCH' }
  $volume=Get-VerifiedWorkspaceVolume $vhd (Join-Path $StateRoot 'workspace-volume') $config.volume_guid
  return @{command=$base;config=$config;volume=$volume;manifest=$manifest;manifest_file=$manifestFile}
}

function Initialize-WorkspaceSecurityApi {
  if (!('DevAIWorkspaceSecurity' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DevAIWorkspaceSecurity {
 [DllImport("advapi32.dll", EntryPoint="GetFileSecurityW", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern bool Get(string path,uint info,byte[] data,uint length,out uint needed);
 [DllImport("advapi32.dll", EntryPoint="SetFileSecurityW", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern bool Set(string path,uint info,byte[] data);
}
'@
  }
}

function Get-NativeWorkspaceSecurity([string]$Path) {
  Initialize-WorkspaceSecurityApi
  [uint32]$needed=0
  $ok=[DevAIWorkspaceSecurity]::Get($Path,5,$null,0,[ref]$needed)
  $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
  if ($ok -or $errorCode -ne 122 -or $needed -le 0 -or $needed -gt 65536) {throw 'WORKSPACE_ROOT_SECURITY_SIZE_FAILED'}
  $bytes=[byte[]]::new($needed)
  if (![DevAIWorkspaceSecurity]::Get($Path,5,$bytes,$needed,[ref]$needed)) {throw 'WORKSPACE_ROOT_SECURITY_READ_FAILED'}
  return [Security.AccessControl.RawSecurityDescriptor]::new($bytes,0)
}

function Set-NativeWorkspaceSecurity([string]$Path,[Security.AccessControl.RawSecurityDescriptor]$Descriptor) {
  Initialize-WorkspaceSecurityApi
  $bytes=[byte[]]::new($Descriptor.BinaryLength)
  $Descriptor.GetBinaryForm($bytes,0)
  # DACL only: preserve owner, SACL/integrity labels and volume identity.
  [uint32]$flags=if ($Descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) {2147483652} else {536870916}
  if (![DevAIWorkspaceSecurity]::Set($Path,$flags,$bytes)) {throw 'WORKSPACE_ROOT_SECURITY_WRITE_FAILED'}
}

function Get-WorkspaceRootPolicy([string]$VhdPath,[string]$Mount,[string]$ExpectedGuid,[string]$ServiceSid) {
  # No arbitrary path/drive is accepted by this higher-level operation.
  if ($ExpectedGuid -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$' -or $ServiceSid -notmatch '^S-1-5-80(?:-\d+){5}$') {throw 'WORKSPACE_ROOT_SECURITY_TARGET_INVALID'}
  Get-VerifiedWorkspaceVolume $VhdPath $Mount $ExpectedGuid | Out-Null
  $descriptor=Get-NativeWorkspaceSecurity $ExpectedGuid
  if ($descriptor.Owner.Value -notin @('S-1-5-18','S-1-5-32-544') -or !$descriptor.DiscretionaryAcl) {throw 'WORKSPACE_ROOT_OWNER_OR_DACL_UNTRUSTED'}
  $foreign=0;$workerList=$false;$workerModify=$false
  foreach($ace in $descriptor.DiscretionaryAcl) {
    if($ace.AceType -eq [Security.AccessControl.AceType]::AccessDenied) {throw 'WORKSPACE_ROOT_DENY_REQUIRES_REVIEW'}
    if($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed) {
      if($ace.SecurityIdentifier.Value -notin @('S-1-5-18','S-1-5-32-544',$ServiceSid)){$foreign++}
      if($ace.SecurityIdentifier.Value -eq $ServiceSid) {
        $workerList=$workerList -or ($ace.AccessMask -band 1) -ne 0
        $workerModify=$workerModify -or ($ace.AccessMask -band 0x1301bf) -eq 0x1301bf
      }
    }
  }
  $expected=[Security.AccessControl.RawSecurityDescriptor]::new(('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;'+$ServiceSid+')'))
  $section=[Security.AccessControl.AccessControlSections]::Access
  return @{descriptor=$descriptor;expected=$expected;guid=$ExpectedGuid;
    matches=($descriptor.GetSddlForm($section) -ceq $expected.GetSddlForm($section));
    summary=@{owner_trusted=$true;protected=[bool]($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected);
      foreign_allow_entries=$foreign;worker_can_list=$workerList;worker_can_modify=$workerModify}}
}

function Set-WorkspaceRootPolicy([string]$VhdPath,[string]$Mount,[string]$ExpectedGuid,[string]$ServiceSid) {
  $policy=Get-WorkspaceRootPolicy $VhdPath $Mount $ExpectedGuid $ServiceSid
  if (!$policy.matches) {Set-NativeWorkspaceSecurity $ExpectedGuid $policy.expected}
  $after=Get-WorkspaceRootPolicy $VhdPath $Mount $ExpectedGuid $ServiceSid
  if (!$after.matches) {throw 'WORKSPACE_ROOT_SECURITY_NOT_VERIFIED'}
  return $after.summary
}

function New-PrivateWorkspaceVolume([string]$VhdPath,[string]$Mount) {
  if (Test-Path -LiteralPath $VhdPath) { throw 'WORKSPACE_IMAGE_ALREADY_EXISTS' }
  $createFile=Join-Path ([IO.Path]::GetDirectoryName($VhdPath)) 'create.txt'
  # DiskPart only creates the new, fixed-path FILE. It never selects a disk,
  # attaches an image, creates a partition or formats anything.
  [IO.File]::WriteAllText($createFile,("create vdisk file=`"$VhdPath`" maximum=128 type=fixed`r`nexit`r`n"))
  & "$env:SystemRoot/System32/diskpart.exe" /s $createFile | Out-Null
  if ($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $VhdPath)) { throw 'WORKSPACE_IMAGE_CREATION_FAILED' }
  Mount-DiskImage -ImagePath $VhdPath -NoDriveLetter | Out-Null
  $disk=Get-VerifiedVhdDisk $VhdPath
  if ($disk.PartitionStyle -ne 'RAW' -or @(Get-Partition -DiskNumber $disk.Number -ErrorAction Ignore).Count) { throw 'NEW_WORKSPACE_IMAGE_NOT_EMPTY' }
  $initialized=Initialize-Disk -InputObject $disk -PartitionStyle GPT -PassThru -Confirm:$false
  $partition=New-Partition -InputObject $initialized -UseMaximumSize -AssignDriveLetter:$false
  Set-Partition -InputObject $partition -NoDefaultDriveLetter:$true -Confirm:$false
  $fresh=Get-VerifiedVhdDisk $VhdPath
  if ($partition.DiskNumber -ne $fresh.Number -or [int][char]$partition.DriveLetter -ne 0) { throw 'NEW_WORKSPACE_PARTITION_MISMATCH' }
  # Formatting is reachable ONLY for the partition just created on our new,
  # verified 128 MiB file-backed disk. Resume never calls this function.
  $formatted=Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel DevAIWorkspace -Confirm:$false
  if ($formatted.FileSystemType -ne 'NTFS') { throw 'WORKSPACE_FORMAT_NOT_VERIFIED' }
  Add-PartitionAccessPath -InputObject $partition -AccessPath ($Mount+'\') -Confirm:$false
  $guid=Get-WorkspaceMountGuid $Mount
  Get-VerifiedWorkspaceVolume $VhdPath $Mount $guid | Out-Null
  Remove-Item -LiteralPath $createFile
  return $guid
}
