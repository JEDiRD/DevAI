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

function Get-RequiredInstallPayloadMembers {
  # Single source for the install-payload allowlist, shared by the installer
  # preflight (package root) and the resume validator (installed tree).
  # Package-relative forward-slash names. Keep aligned with the release
  # contract (REQUIRED_PACKAGE_MEMBERS in tools/release_lib.py) and the
  # builder sandbox contract.
  return @('host-runtime/python.exe','sandbox-runtime/python.exe','sandbox-runtime/synthetic_process.py','control/worker_agent/windows_service.py','control/worker_agent/volume_host.py')
}

function Assert-PartialWorkerInstall([string]$InstallRoot,[string]$StateRoot,$ReleaseManifest,[switch]$ExistingService,[string]$PreviousServiceHash,[string]$PreviousWorkspaceHash) {
  # RELEASE IDENTITY ONLY. This validator receives a validated release manifest from
  # Read-ReleaseManifest. There is deliberately no dual-shape handling and no
  # package.json fallback: exactly one release format exists.
  $releaseDigests=@{}
  if ($null -eq $ReleaseManifest) { throw 'RELEASE_DIGEST_SOURCE_UNAVAILABLE' }
  foreach ($key in $ReleaseManifest.Files.Keys) { $releaseDigests[$key]=[string]$ReleaseManifest.Files[$key].sha256 }
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
  #
  # TARGET values are validated against TARGET POLICY. They are deliberately
  # NOT compared to package-owned data: the immutable release manifest carries
  # no concrete worker_id, api_base_url or fixture path, so such a comparison
  # is no longer meaningful and would blur the two trust domains.
  # Read directly: Assert-ManagedNoReparse already ran over the state tree above,
  # and this validator is used where path/Test-Path probing is unavailable.
  $config=Get-Content -LiteralPath $configFile -Raw | ConvertFrom-Json
  if ($null -eq $config) { throw 'PARTIAL_INSTALL_CONFIG_MISMATCH' }
  $keys=@('worker_id','api_base_url','heartbeat_seconds','poll_seconds','credential_path','service_sid','volume_guid','sandbox_runtime','sandbox_executable_sha256','sandbox_payload_sha256','personal_denial_fixture')
  if (@($config.PSObject.Properties.Name | Where-Object {$_ -notin $keys}).Count) { throw 'PARTIAL_INSTALL_CONFIG_MISMATCH' }
  if ($config.service_sid -ne $serviceSid -or
      $config.credential_path -ne (Join-Path $StateRoot 'credentials/worker.dpapi') -or
      $config.sandbox_runtime -ne (Join-Path $InstallRoot 'sandbox-runtime')) { throw 'PARTIAL_INSTALL_CONFIG_MISMATCH' }
  # Target identity policy: non-empty UUID plus the UNCHANGED ApiBaseUrl matrix.
  $parsedId=[Guid]::Empty
  if (![Guid]::TryParse([string]$config.worker_id,[ref]$parsedId) -or $parsedId -eq [Guid]::Empty) { throw 'PARTIAL_INSTALL_CONFIG_MISMATCH' }
  if (!(Test-TargetApiBaseUrl ([string]$config.api_base_url))) { throw 'PARTIAL_INSTALL_CONFIG_MISMATCH' }
  # The fixture path must be a genuine absolute target path. The full ACL
  # witness check (protected DACL, exactly three ACEs, no service-SID ACE) is
  # enforced where it is created (New-TargetPersonalDenialFixture) and again by
  # the installer after fixture creation; it is deliberately NOT re-derived here,
  # because this validator must stay usable where ACL inspection is unavailable.
  if ([string]::IsNullOrWhiteSpace([string]$config.personal_denial_fixture) -or
      ![IO.Path]::IsPathRooted([string]$config.personal_denial_fixture)) { throw 'INVALID_PERSONAL_FIXTURE_PATH' }
  foreach ($forbidden in @($env:ProgramData,$env:ProgramFiles,[IO.Path]::GetTempPath())) {
    if (![string]::IsNullOrWhiteSpace($forbidden) -and
        ([string]$config.personal_denial_fixture).StartsWith($forbidden,[StringComparison]::OrdinalIgnoreCase)) { throw 'PERSONAL_FIXTURE_FORBIDDEN_LOCATION' }
  }
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
    # Immutable release source. NEVER the installed-tree manifest being checked.
    $packaged=if ($releaseDigests.ContainsKey($entry.Name)) { $releaseDigests[$entry.Name] } else { $null }
    if ($ExistingService) {
      $allowed=if ($entry.Name -eq 'control/worker_agent/windows_service.py') {@($PreviousServiceHash,$packaged)}
        elseif ($entry.Name -eq 'control/worker_agent/workspace.py' -and $PreviousWorkspaceHash) {@($PreviousWorkspaceHash,$packaged)} else {@($packaged)}
      if (!$packaged -or $entry.Value -notin $allowed) { throw 'DIAGNOSTIC_PACKAGE_RUNTIME_MISMATCH' }
    } elseif (!$packaged -or ($entry.Name -ne 'control/worker_agent/volume_host.py' -and $entry.Value -ne $packaged)) { throw 'RESUME_PACKAGE_RUNTIME_MISMATCH' }
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
  foreach ($required in (Get-RequiredInstallPayloadMembers)) {
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

# ===========================================================================
# RH-B 5A-2: authoritative helpers, two DISTINCT trust domains.
#
#   A. IMMUTABLE RELEASE  -- manifest.json and the payload it authenticates.
#   B. TARGET STATE       -- service.json, personal fixture, credential state.
#
# These families are deliberately separate. An immutable helper never reads
# service.json; a target helper never authenticates release payload.
# ===========================================================================

# --- A. IMMUTABLE RELEASE -------------------------------------------------

function Get-ManifestFormat {
  # Storage format (JSON contract) and identity serialization (MANIFEST_FORMAT_V2)
  # are different concepts and are named separately on purpose.
  'DEVAI_PACKAGE_MANIFEST'
}

function Get-ManifestIdentityFormat { 'MANIFEST_FORMAT_V2' }

function Read-ReleaseManifest {
  # Validates schema and entry model BEFORE any entry is trusted.
  param([Parameter(Mandatory=$true)][string]$PackageRoot)
  $manifestPath=Join-Path $PackageRoot 'manifest.json'
  if (!(Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'MANIFEST_MISSING' }
  $raw=[IO.File]::ReadAllBytes($manifestPath)
  if ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF) { throw 'MANIFEST_HAS_BOM' }
  # Windows PowerShell 5.1 pipes a byte array into ConvertFrom-Json element by
  # element, which silently yields an empty document. Decode first.
  $text=[Text.Encoding]::UTF8.GetString($raw)
  try { $document=$text | ConvertFrom-Json } catch { throw 'MANIFEST_NOT_VALID_JSON' }
  if ($document.manifest_format -ne (Get-ManifestFormat)) { throw 'UNSUPPORTED_MANIFEST_FORMAT' }
  if ([int]$document.manifest_schema_version -ne 1) { throw 'UNSUPPORTED_MANIFEST_SCHEMA_VERSION' }
  $files=@($document.files)
  if ($files.Count -eq 0) { throw 'MANIFEST_FILES_MISSING' }
  $seen=@{}
  $table=@{}
  foreach ($entry in $files) {
    foreach ($field in @('path','sha256','size')) {
      if ($null -eq $entry.$field) { throw "MANIFEST_ENTRY_FIELD_MISSING:$field" }
    }
    $path=[string]$entry.path
    if ([string]::IsNullOrWhiteSpace($path)) { throw 'MANIFEST_ENTRY_PATH_INVALID' }
    if ([IO.Path]::IsPathRooted($path) -or $path.Contains('\') -or $path.Contains(':')) { throw "UNSAFE_MANIFEST_PATH:$path" }
    foreach ($segment in ($path -split '/')) {
      if ($segment -eq '' -or $segment -eq '.' -or $segment -eq '..') { throw "UNSAFE_MANIFEST_PATH:$path" }
    }
    $folded=$path.ToLowerInvariant()
    if ($seen.ContainsKey($folded)) { throw "MANIFEST_PATH_COLLISION:$path" }
    $seen[$folded]=$true
    if ([string]$entry.sha256 -notmatch '^[0-9a-f]{64}$') { throw "MANIFEST_SHA256_MALFORMED:$path" }
    $table[$path]=@{ sha256=[string]$entry.sha256; size=[int64]$entry.size }
  }
  $aggregate=$document.identity.aggregate_sha256
  if ([string]$aggregate -notmatch '^[0-9a-f]{64}$') { throw 'MANIFEST_IDENTITY_AGGREGATE_MALFORMED' }
  return [pscustomobject]@{
    Document=$document; Files=$table; Aggregate=$aggregate
    IdentityFormat=[string]$document.identity.format
    PolicyRequirements=@($document.policy_requirements)
    Runtime=$document.runtime; DependencyLocks=$document.dependency_locks
  }
}

function Assert-PackageEntryName {
  # Name-shape validation for an entry key of an INSTALLED-TREE manifest (a
  # different artifact from the release-root manifest contract). Rejects rooted
  # paths, traversal, empty segments, '.', and drive-qualified names.
  param([string]$Name)
  $parts=$Name -split '[\\/]'
  if ([string]::IsNullOrWhiteSpace($Name) -or [IO.Path]::IsPathRooted($Name) -or
      $parts -contains '..' -or $parts -contains '.' -or $parts -contains '' -or $Name.Contains(':')) {
    throw 'UNSAFE_PACKAGE_PATH'
  }
}

function Initialize-LongPathNative {
  # Canonicalization support. Windows PowerShell 5.1 runs on .NET Framework 4.x,
  # which does NOT provide [IO.Path]::GetRelativePath (that API arrived with
  # .NET Core 2.0 / .NET Standard 2.1). Resolving 8.3 short components therefore
  # goes through the Win32 API, which is available on every supported runtime.
  # Add-Type is guarded so repeated dot-sourcing stays idempotent.
  if ('DevAi.LongPathNative' -as [type]) { return }
  Add-Type @'
namespace DevAi {
  public static class LongPathNative {
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
    public static extern uint GetLongPathName(string lpszShortPath, System.Text.StringBuilder lpszLongPath, uint cchBuffer);
  }
}
'@ -ErrorAction Stop
}

function Get-CanonicalLongPath {
  # Resolves any 8.3 short component to its long spelling. Fails closed: an
  # unresolvable path is never silently treated as already-canonical, because a
  # wrong canonical form would corrupt the containment check downstream.
  param([Parameter(Mandatory=$true)][string]$Path)
  Initialize-LongPathNative
  $buffer = New-Object System.Text.StringBuilder 32768
  $needed = [DevAi.LongPathNative]::GetLongPathName($Path, $buffer, 32768)
  if ($needed -eq 0) { throw "PACKAGE_PATH_CANONICALIZATION_FAILED:$Path" }
  if ($needed -gt 32768) { throw "PACKAGE_PATH_CANONICALIZATION_TRUNCATED:$Path" }
  return $buffer.ToString()
}

function Get-CanonicalPackageRelativePath {
  # SINGLE authoritative derivation of a package member's manifest-relative path.
  #
  # It never subtracts a length from the caller-supplied spelling. That previous
  # behaviour assumed $PackageRoot and the enumerated FullName used the same
  # lexical form, which is false whenever the root is reached through an 8.3
  # alias -- hosted Windows runners expose TEMP as an 8.3 alias of the user
  # profile directory -- and it rejected valid packages as
  # UNMANIFESTED_PACKAGE_FILE.
  #
  # Order of operations, and each step is a hard gate:
  #   1. canonicalize root and member to the SAME long-form representation
  #   2. absolute-path normalization of both
  #   3. directory-BOUNDARY-aware containment (not a bare prefix compare, so a
  #      sibling such as C:\pkg2\evil cannot pass as C:\pkg)
  #   4. Windows case-insensitive comparison
  #   5. relative path derived ONLY after canonicalization
  #   6. separators normalized to '/' for manifest comparison
  #   7. empty / '.' / '..' / drive-qualified remnants rejected
  # Anything that does not resolve strictly inside the root fails closed.
  param(
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$CandidatePath
  )
  $rootFull = [IO.Path]::GetFullPath((Get-CanonicalLongPath -Path $PackageRoot)).TrimEnd('\','/')
  $candFull = [IO.Path]::GetFullPath((Get-CanonicalLongPath -Path $CandidatePath))
  if ($candFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
    throw "PACKAGE_MEMBER_IS_ROOT:$CandidatePath"
  }
  if (!$candFull.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "PACKAGE_MEMBER_OUTSIDE_ROOT:$CandidatePath"
  }
  $relative = $candFull.Substring($rootFull.Length + 1)
  if ([string]::IsNullOrWhiteSpace($relative)) { throw "PACKAGE_MEMBER_RELATIVE_EMPTY:$CandidatePath" }
  $relative = $relative.Replace('\','/')
  if ($relative.Contains(':')) { throw "PACKAGE_MEMBER_RELATIVE_DRIVE_QUALIFIED:$relative" }
  foreach ($segment in $relative.Split('/')) {
    if ($segment -eq '' -or $segment -eq '.' -or $segment -eq '..') {
      throw "PACKAGE_MEMBER_RELATIVE_UNSAFE:$relative"
    }
  }
  return $relative
}

function Assert-ManifestPathSafe {
  # Containment: the resolved member must stay inside the release root.
  param([string]$PackageRoot,[string]$Relative)
  $rootFull=[IO.Path]::GetFullPath($PackageRoot).TrimEnd('\','/')
  $target=[IO.Path]::GetFullPath((Join-Path $rootFull $Relative))
  if (!($target.StartsWith($rootFull + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase))) {
    throw "MANIFEST_PATH_ESCAPE:$Relative"
  }
}

function Assert-ManifestPayload {
  # Full immutable integrity gate. Everything here precedes any target mutation.
  param([Parameter(Mandatory=$true)][string]$PackageRoot,$Manifest)
  # Out-Null is load-bearing: Assert-ManagedNoReparse returns the item, and
  # without this a DirectoryInfo would join the $verified table in this
  # function's output, so callers would receive Object[] instead of Hashtable.
  Assert-ManagedNoReparse $PackageRoot | Out-Null
  for ($parent=$PackageRoot; $null -ne $parent; $parent=$parent.Parent) {
    if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PACKAGE_ANCESTOR_REPARSE_POINT' }
  }
  $verified=@{}
  foreach ($relative in ($Manifest.Files.Keys | Sort-Object)) {
    Assert-ManifestPathSafe $PackageRoot $relative
    $full=[IO.Path]::GetFullPath((Join-Path $PackageRoot $relative))
    if (!(Test-Path -LiteralPath $full -PathType Leaf)) { throw "MANIFEST_FILE_MISSING:$relative" }
    $item=Get-Item -LiteralPath $full -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "MANIFEST_REPARSE_MEMBER:$relative" }
    if ($item.Length -ne $Manifest.Files[$relative].size) { throw "MANIFEST_SIZE_MISMATCH:$relative" }
    $digest=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($digest -cne $Manifest.Files[$relative].sha256) { throw "MANIFEST_HASH_MISMATCH:$relative" }
    $verified[$relative]=$digest
  }
  foreach ($item in (Get-ChildItem -LiteralPath $PackageRoot -Recurse -Force -File)) {
    $relative=Get-CanonicalPackageRelativePath -PackageRoot $PackageRoot -CandidatePath $item.FullName
    if ($relative -eq 'manifest.json') { continue }
    if (!$verified.ContainsKey($relative)) { throw "UNMANIFESTED_PACKAGE_FILE:$relative" }
  }
  return $verified
}

function Get-ManifestV2Serialization {
  # MANIFEST_FORMAT_V2 canonical serialization, rebuilt here from ACTUAL
  # payload bytes: UTF-8, no BOM, LF separators, trailing LF, first line
  # "# MANIFEST_FORMAT_V2", then UTF-8 byte-sorted identity lines.
  #
  # This is an identity algorithm, NOT the storage format. It is recomputed
  # from verified bytes rather than read from the document, so a manifest
  # cannot validate itself by asserting its own aggregate.
  param([Parameter(Mandatory=$true)][string]$PackageRoot,$Manifest)
  $sb=New-Object Text.StringBuilder
  [void]$sb.Append('# ' + (Get-ManifestIdentityFormat) + "`n")
  $sorted=[System.Collections.Generic.List[string]]::new()
  foreach ($key in $Manifest.Files.Keys) { $sorted.Add($key) }
  $sorted.Sort([System.Collections.Generic.Comparer[string]]::Create(
    [System.Comparison[string]]{ param($a,$b)
      $x=[Text.Encoding]::UTF8.GetBytes($a); $y=[Text.Encoding]::UTF8.GetBytes($b)
      $n=[Math]::Min($x.Length,$y.Length)
      for ($i=0;$i -lt $n;$i++) { if ($x[$i] -ne $y[$i]) { return $x[$i] - $y[$i] } }
      return $x.Length - $y.Length } ))
  foreach ($relative in $sorted) {
    $entry=$Manifest.Files[$relative]
    [void]$sb.Append($entry.sha256 + '  ' + $entry.size + '  ' + $relative + "`n")
  }
  return [Text.Encoding]::UTF8.GetBytes($sb.ToString())
}

function Assert-ManifestIdentityAggregate {
  # INTERNAL CONSISTENCY ONLY. This proves the document's stored aggregate
  # matches the payload it describes. It is NOT release authenticity: only an
  # independently trusted digest (the launcher's ExpectedManifestSHA256)
  # authenticates the manifest itself. Never present this as authenticity.
  param([Parameter(Mandatory=$true)][string]$PackageRoot,$Manifest)
  $bytes=Get-ManifestV2Serialization $PackageRoot $Manifest
  $sha=[Security.Cryptography.SHA256]::Create()
  try { $digest=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
  finally { $sha.Dispose() }
  if ($digest -cne $Manifest.Aggregate) { throw 'MANIFEST_IDENTITY_AGGREGATE_MISMATCH' }
  return $digest
}

function Assert-ManifestRequiredMembers {
  param($Manifest,[string[]]$Required)
  foreach ($member in $Required) {
    if (!$Manifest.Files.ContainsKey($member)) { throw "REQUIRED_MANIFEST_MEMBER_MISSING:$member" }
  }
}

function Get-ManifestFileDigest {
  param($Manifest,[string]$Relative)
  if (!$Manifest.Files.ContainsKey($Relative)) { throw "MANIFEST_FILE_MISSING:$Relative" }
  return $Manifest.Files[$Relative].sha256
}

function Assert-ManifestRuntimeIdentity {
  param($Manifest,$RuntimeLock)
  if ($null -eq $Manifest.Runtime) { throw 'MANIFEST_RUNTIME_IDENTITY_MISSING' }
  if ([string]$Manifest.Runtime.python_version -ne [string]$RuntimeLock.python_version) { throw 'RUNTIME_VERSION_MISMATCH' }
  if ([string]$Manifest.Runtime.source_sha256 -ne [string]$RuntimeLock.source_sha256) { throw 'RUNTIME_SHA256_MISMATCH' }
}

function Assert-ManifestDependencyLockIdentity {
  param($Manifest,$LockMetadata,[string]$Platform)
  $key=if ($Platform -eq 'windows') { 'windows' } else { 'linux' }
  if ($null -eq $Manifest.DependencyLocks) { throw 'MANIFEST_LOCK_IDENTITY_MISSING' }
  $declared=$Manifest.DependencyLocks.$key
  if ($null -eq $declared) { throw "MANIFEST_LOCK_IDENTITY_MISSING:$key" }
  if ([string]$declared.sha256 -ne [string]$LockMetadata.$key.lock_sha256) { throw "LOCK_IDENTITY_MISMATCH:$key" }
}

# --- B. TARGET STATE ------------------------------------------------------

function Test-TargetApiBaseUrl {
  # EXISTING tested policy, preserved verbatim. This is NOT "HTTPS required":
  # the established behaviour accepts http AND https, and requires a literal
  # IP host that is loopback or 100.64.0.0/10 (CGNAT). Do not tighten or broaden.
  param([string]$Url)
  $origin=$null; $address=$null
  if (![Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$origin) -or
      $origin.Scheme -notin @('http','https') -or $origin.UserInfo -or $origin.AbsolutePath -ne '/' -or
      $origin.Query -or $origin.Fragment -or ![Net.IPAddress]::TryParse($origin.Host,[ref]$address)) { return $false }
  $bytes=$address.GetAddressBytes()
  if (![Net.IPAddress]::IsLoopback($address) -and !($bytes.Length -eq 4 -and $bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127)) { return $false }
  return $true
}

function Assert-TargetApiBaseUrl { param([string]$Url) if (!(Test-TargetApiBaseUrl $Url)) { throw 'INVALID_API_BASE_URL' } }

function Resolve-TargetIdentity {
  # CLI and ExistingConfig may both supply a value; they must AGREE.
  # No precedence rule: disagreement fails closed so reinstall cannot silently
  # change worker identity or endpoint.
  param([string]$CliWorkerId,[string]$CliApiBaseUrl,$Config)
  $workerId=$CliWorkerId; $apiBaseUrl=$CliApiBaseUrl
  if ($null -ne $Config) {
    $existingWorker=[string]$Config.worker_id
    $existingApi=[string]$Config.api_base_url
    if ([string]::IsNullOrWhiteSpace($existingWorker)) { throw 'EXISTING_CONFIG_WORKER_ID_MISSING' }
    if ([string]::IsNullOrWhiteSpace($existingApi)) { throw 'EXISTING_CONFIG_API_BASE_URL_MISSING' }
    if ([string]::IsNullOrWhiteSpace($workerId)) { $workerId=$existingWorker }
    elseif ($workerId -ine $existingWorker) { throw 'WORKER_ID_CONFLICT' }
    if ([string]::IsNullOrWhiteSpace($apiBaseUrl)) { $apiBaseUrl=$existingApi }
    elseif ($apiBaseUrl -ine $existingApi) { throw 'API_BASE_URL_CONFLICT' }
  }
  if ([string]::IsNullOrWhiteSpace($workerId)) { throw 'WORKER_ID_REQUIRED' }
  if ([string]::IsNullOrWhiteSpace($apiBaseUrl)) { throw 'API_BASE_URL_REQUIRED' }
  $parsed=[Guid]::Empty
  if (![Guid]::TryParse($workerId,[ref]$parsed) -or $parsed -eq [Guid]::Empty) { throw 'INVALID_WORKER_ID' }
  Assert-TargetApiBaseUrl $apiBaseUrl
  return [pscustomobject]@{ WorkerId=$workerId; ApiBaseUrl=$apiBaseUrl }
}

function Resolve-InstallerTargetIdentity {
  # Single implementation of the install-worker.ps1 TARGET IDENTITY glue.
  # The -ExistingConfig PATH parameter and the loaded config OBJECT must never
  # share a case-insensitive PowerShell name: $ExistingConfig is a typed
  # [string], so assigning the config object to a same-spelled local would
  # coerce $null to '' and the object to String, and every fresh install
  # would fail closed with EXISTING_CONFIG_WORKER_ID_MISSING. The loaded
  # object therefore lives in $loadedExistingConfig, which is spelled
  # distinctly. Read-only; never mutates the target.
  param([string]$WorkerId,[string]$ApiBaseUrl,[string]$ExistingConfig)
  $loadedExistingConfig=$null
  if (-not [string]::IsNullOrWhiteSpace($ExistingConfig)) {
    if (!(Test-Path -LiteralPath $ExistingConfig -PathType Leaf)) { throw 'EXISTING_CONFIG_MISSING' }
    $loadedExistingConfig=Read-TargetServiceConfig -ConfigFile $ExistingConfig
    if ($null -eq $loadedExistingConfig) { throw 'EXISTING_CONFIG_INVALID' }
  }
  return Resolve-TargetIdentity -CliWorkerId $WorkerId -CliApiBaseUrl $ApiBaseUrl -Config $loadedExistingConfig
}

function Read-TargetServiceConfig {
  param([Parameter(Mandatory=$true)][string]$ConfigFile)
  if (!(Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { return $null }
  # Out-Null is load-bearing: Assert-ManagedNoReparse returns the item, and
  # without this the FileInfo would join the config object in this function's
  # output, so callers would receive Object[] instead of the config document.
  Assert-ManagedNoReparse $ConfigFile | Out-Null
  return (Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json)
}

function New-TargetPersonalDenialFixture {
  # Target-side creation of the personal-profile denial witness.
  #
  # Reproduces the EXACT security model previously implemented by
  # worker_agent.prepare_personal_fixture: a protected (non-inherited) DACL
  # with exactly three full-control allow ACEs (LOCAL SYSTEM, BUILTIN
  # Administrators, and the installing operator). The worker service identity
  # is deliberately NOT granted an ACE, which is what makes the runtime
  # service_personal_profile_denied gate meaningful.
  #
  # Location is the installing operator's private profile root, and is never
  # under AppData (which desktop-app package virtualisation would redirect).
  param([string]$ProfileRoot,[string]$OwnerSid)
  if ([string]::IsNullOrWhiteSpace($ProfileRoot) -or ![IO.Path]::IsPathRooted($ProfileRoot)) { throw 'INVALID_PROFILE_ROOT' }
  if ([string]::IsNullOrWhiteSpace($OwnerSid)) { throw 'INVALID_PROFILE_OWNER' }
  $leaf=Join-Path $ProfileRoot 'AppData'
  if ((Split-Path -Leaf $ProfileRoot) -eq 'AppData') { throw 'PROFILE_ROOT_INSIDE_APPDATA' }
  $probeRoot=Join-Path $ProfileRoot 'DevAIWorkerAccessProbe'
  $fixture=Join-Path $probeRoot 'service-access-denial.fixture'
  foreach ($path in @($ProfileRoot,$probeRoot)) {
    if (Test-Path -LiteralPath $path) {
      Assert-ManagedNoReparse $path | Out-Null
    } else {
      [IO.Directory]::CreateDirectory($path) | Out-Null
      Assert-ManagedNoReparse $path | Out-Null
    }
    $sddlModel='D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;' + $OwnerSid + ')'
    # The SDDL above is the reference model. It is applied PROGRAMMATICALLY
    # rather than through SetSecurityDescriptorSddlForm, because round-tripping
    # an SDDL that omits the SACL makes SetAccessControl demand SeSecurityPrivilege.
    # Protected DACL (D:P) + exactly three inheritable full-control allow ACEs
    # (SYSTEM, Administrators, installing owner) and NO other ACE, in particular
    # no service SID. This is byte-for-byte the same access model.
    $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    $directoryAcl=New-Object Security.AccessControl.DirectorySecurity
    $directoryAcl.SetAccessRuleProtection($true,$false)
    foreach ($identity in @('S-1-5-18','S-1-5-32-544',$OwnerSid)) {
      $directoryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        [Security.Principal.SecurityIdentifier]::new($identity),'FullControl',$inherit,'None','Allow')))
    }
    ([IO.DirectoryInfo]$path).SetAccessControl($directoryAcl)
    # The witness file must itself carry a protected three-ACE DACL rather than
    # merely inheriting one, so it is set explicitly with no inheritance.
    $fileAcl=New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetAccessRuleProtection($true,$false)
    foreach ($identity in @('S-1-5-18','S-1-5-32-544',$OwnerSid)) {
      $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        [Security.Principal.SecurityIdentifier]::new($identity),'FullControl','None','None','Allow')))
    }
  }
  if (Test-Path -LiteralPath $fixture) { Assert-ManagedNoReparse $fixture | Out-Null }
  else { [IO.File]::WriteAllText($fixture,"Non-secret DevAI dedicated-service ACL acceptance fixture.`n") }
  # Applied after creation so an existing file is normalised to the same model.
  ([IO.FileInfo]$fixture).SetAccessControl($fileAcl)
  Assert-ManagedNoReparse $fixture | Out-Null
  Assert-TargetPersonalDenialFixture $fixture $OwnerSid | Out-Null
  return $fixture
}

function Assert-TargetPersonalDenialFixture {
  # Validates the fixture is a genuine denial witness: absolute, non-reparse,
  # outside shared/system locations, protected ACL with exactly the intended
  # SID set, and NOT readable by the worker service identity.
  param([string]$Fixture,[string]$OwnerSid,[string]$ServiceSid='')
  if ([string]::IsNullOrWhiteSpace($Fixture) -or ![IO.Path]::IsPathRooted($Fixture)) { throw 'INVALID_PERSONAL_FIXTURE_PATH' }
  for ($parent=$Fixture; $null -ne $parent; $parent=$parent.Parent) {
    if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'INVALID_PERSONAL_FIXTURE_PATH' }
  }
  foreach ($forbidden in @($env:ProgramData,$env:ProgramFiles,[IO.Path]::GetTempPath())) {
    if (![string]::IsNullOrWhiteSpace($forbidden) -and
        $Fixture.StartsWith($forbidden,[StringComparison]::OrdinalIgnoreCase)) { throw 'PERSONAL_FIXTURE_FORBIDDEN_LOCATION' }
  }
  if (!(Test-Path -LiteralPath $Fixture -PathType Leaf)) { throw 'PERSONAL_FIXTURE_MISSING' }
  foreach ($path in @($Fixture,(Split-Path -Parent $Fixture))) {
    $acl=Get-Acl -LiteralPath $path
    if (!$acl.AreAccessRulesProtected) { throw 'PERSONAL_FIXTURE_ACL_INHERITED' }
    $sids=@($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
    $expected=@('S-1-5-18','S-1-5-32-544',$OwnerSid) | Sort-Object -Unique
    if (($sids -join ',') -cne ($expected -join ',')) { throw 'PERSONAL_FIXTURE_ACL_SID_SET_MISMATCH' }
    foreach ($rule in $acl.Access) {
      if ($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in @('S-1-1-0','S-1-5-32-545','S-1-5-11')) {
        throw 'PERSONAL_FIXTURE_ACL_BROAD_ACE'
      }
      if ($ServiceSid -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $ServiceSid) {
        throw 'PERSONAL_FIXTURE_SERVICE_READ_GRANTED'
      }
    }
  }
  return $true
}

function Test-TargetCredentialPresent {
  param([Parameter(Mandatory=$true)][string]$CredentialPath)
  return (Test-Path -LiteralPath $CredentialPath -PathType Leaf)
}

function Invoke-TargetCredentialProvisioning {
  # Calls the packaged pinned runtime with the EXISTING, byte-identical
  # worker_agent.provision primitive. --worker-id and --store-path are
  # non-secret. The token is delivered ONLY over redirected stdin.
  param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$RuntimeRoot,
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [Parameter(Mandatory=$true)][string]$CredentialPath,
    [Parameter(Mandatory=$true)][string]$Token
  )
  $python=Join-Path $RuntimeRoot 'python.exe'
  if (!(Test-Path -LiteralPath $python -PathType Leaf)) { throw 'PROVISION_RUNTIME_MISSING' }
  $psi=New-Object Diagnostics.ProcessStartInfo
  $psi.FileName=$python
  # No token in argv. Only non-secret identity and destination.
  $psi.Arguments='-m worker_agent.provision --worker-id ' + $WorkerId + ' --store-path "' + $CredentialPath + '"'
  $psi.WorkingDirectory=$InstallRoot
  $psi.UseShellExecute=$false
  $psi.RedirectStandardInput=$true
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $process=[Diagnostics.Process]::Start($psi)
  try {
    # Written to the child's stdin and immediately dropped from this buffer.
    $process.StandardInput.Write($Token)
    $process.StandardInput.Close()
    $process.StandardInput=$null
    $Token=$null
    $process.WaitForExit()
  } finally {
    if (!$process.HasExited) { $process.Kill() }
  }
  if ($process.ExitCode -ne 0) { throw 'CREDENTIAL_PROVISIONING_FAILED' }
  if (!(Test-TargetCredentialPresent $CredentialPath)) { throw 'CREDENTIAL_PROVISIONING_FAILED' }
  return $true
}
