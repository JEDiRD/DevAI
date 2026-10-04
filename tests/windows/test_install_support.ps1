param([string]$Support=(Join-Path $PSScriptRoot '../../deploy/windows/install-support.ps1'))
$ErrorActionPreference='Stop'
. $Support
$script:recorded=$null
$script:scCalls=@()
$script:createResult=0
$script:wrongIdentity=$false
function Invoke-CimMethod { param($Namespace,$ClassName,$MethodName,$Arguments)
  if ($Namespace -ne 'root/cimv2' -or $ClassName -ne 'Win32_Service' -or $MethodName -ne 'Create') {throw 'WRONG_CIM_OPERATION'}
  $script:recorded=$Arguments
  return [pscustomobject]@{ReturnValue=$script:createResult}
}
function sc.exe {
  $script:scCalls+=,@($args)
  $global:LASTEXITCODE=0
}
function Get-CimInstance {param($ClassName,$Filter)
  return [pscustomobject]@{PathName=$script:recorded.PathName;StartName=$(if($script:wrongIdentity){'LocalSystem'}else{'NT SERVICE\DevAIWorker'});StartMode='Auto'}
}
$command=Get-WorkerServiceCommand 'C:\Program Files\DevAIWorker' 'C:\ProgramData\DevAIWorker\service.json'
$expected='"C:\Program Files\DevAIWorker\host-runtime\python.exe" -I -S -B -m worker_agent.windows_service --config "C:\ProgramData\DevAIWorker\service.json"'
if ($command -cne $expected) {throw 'BINARY_PATH_QUOTING_TEST_FAILED'}
New-WorkerService $command
if ($script:recorded.PathName -cne $expected -or $script:recorded.StartName -ne 'NT SERVICE\DevAIWorker' -or
    $null -ne $script:recorded.StartPassword -or $script:recorded.ServiceType -ne 16 -or
    $script:recorded.DesktopInteract -or $script:recorded.ServiceDependencies.Count -ne 1 -or
    $script:recorded.ServiceDependencies[0] -ne 'DevAIWorkerVolumes') {throw 'SERVICE_CONSTRUCTION_TEST_FAILED'}
if (($script:scCalls[0] -join '|') -ne 'config|DevAIWorker|start=|delayed-auto') {throw 'DELAYED_START_TEST_FAILED'}
$script:createResult=2
$script:scCalls=@()
try {New-WorkerService $command;throw 'SERVICE_CREATE_ERROR_ACCEPTED'}
catch {if($_.Exception.Message -ne 'WORKER_SERVICE_CREATION_FAILED_2'){throw}}
if ($script:scCalls.Count) {throw 'CONFIGURED_AFTER_CREATE_FAILURE'}
$script:createResult=0;$script:wrongIdentity=$true
try {New-WorkerService $command;throw 'WRONG_IDENTITY_ACCEPTED'}
catch {if($_.Exception.Message -ne 'SERVICE_IDENTITY_OR_PATH_NOT_VERIFIED'){throw}}
$script:scCalls=@()
Set-WorkerServiceRecovery
if ($script:scCalls.Count -ne 5 -or ($script:scCalls[-1] -join '|') -ne 'sidtype|DevAIWorker|unrestricted') {throw 'SERVICE_RECOVERY_POLICY_TEST_FAILED'}

# Preserve the exact original manifest inheritance without permitting broader
# identities or Worker write rights. Inventory/ACL queries are mocked only.
$tokens=$null;$errors=$null
$supportAst=[Management.Automation.Language.Parser]::ParseFile($Support,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'SUPPORT_SYNTAX_INVALID'}
$noReparse=$supportAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-ManagedNoReparse'},$true)
function Assert-ManagedNoReparse {param($Path) return $null}
$adminSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$workerSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
$script:acl=[pscustomobject]@{Owner=$adminSid.Translate([Security.Principal.NTAccount]).Value;AreAccessRulesProtected=$false;
  Access=@([Security.AccessControl.FileSystemAccessRule]::new($adminSid,'FullControl','Allow'),
           [Security.AccessControl.FileSystemAccessRule]::new($workerSid,'Read','Allow'))}
function Get-Acl {param($LiteralPath) return $script:acl}
try {Assert-ManagedPrivateAcl 'manifest.json' $workerSid.Value;throw 'INHERITANCE_ACCEPTED_WITHOUT_EXCEPTION'}
catch {if($_.Exception.Message -ne 'MANAGED_INSTALL_ACL_UNSAFE'){throw}}
Assert-ManagedPrivateAcl 'manifest.json' $workerSid.Value -AllowInherited
$script:acl.Access+=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Read','Allow')
try {Assert-ManagedPrivateAcl 'manifest.json' $workerSid.Value -AllowInherited;throw 'WORLD_READABLE_MANIFEST_ACCEPTED'}
catch {if($_.Exception.Message -ne 'MANAGED_INSTALL_ACL_UNSAFE'){throw}}
$script:acl.Access=@([Security.AccessControl.FileSystemAccessRule]::new($workerSid,'Modify','Allow'))
try {Assert-ManagedPrivateAcl 'manifest.json' $workerSid.Value -AllowInherited;throw 'WRITABLE_MANIFEST_ACCEPTED'}
catch {if($_.Exception.Message -ne 'MANAGED_INSTALL_ACL_UNSAFE'){throw}}
. ([ScriptBlock]::Create($noReparse.Extent.Text))

# Fake only read-only storage inventory. No native storage mutations occur.
$script:vhd='C:\ProgramData\DevAIWorker\volumes\workspace.vhdx'
$script:mount='C:\ProgramData\DevAIWorker\workspace-volume'
$script:guid='\\?\Volume{25914664-0000-0000-0000-010000000000}\'
$script:image=[pscustomobject]@{ImagePath=$script:vhd;Attached=$true}
$script:disk=[pscustomobject]@{Number=7;IsBoot=$false;IsSystem=$false;BusType='File Backed Virtual';Size=134217728;Location=$script:vhd}
$script:partition=[pscustomobject]@{DiskNumber=7;Type='IFS';DriveLetter=[char]0;AccessPaths=@(($script:mount+'\'),$script:guid)}
$script:volume=[pscustomobject]@{FileSystemType='NTFS';FileSystemLabel='DevAIWorkspace';HealthStatus='Healthy';Size=133103616}
function Get-DiskImage {param($ImagePath) return $script:image}
function Get-Disk {param([Parameter(ValueFromPipeline=$true)]$InputObject) process{return $script:disk}}
function Get-Partition {param($DiskNumber) if($DiskNumber -ne 7){throw 'WRONG_DISK_QUERIED'};return $script:partition}
function Get-Volume {param([Parameter(ValueFromPipeline=$true)]$InputObject) process{return $script:volume}}
function Get-WorkspaceMountGuid {param($Mount) return $script:guid}
function Format-Volume {throw 'STORAGE_MUTATION_DURING_VERIFICATION'}
function Initialize-Disk {throw 'STORAGE_MUTATION_DURING_VERIFICATION'}
function Mount-DiskImage {throw 'STORAGE_MUTATION_DURING_VERIFICATION'}
$proof=Get-VerifiedWorkspaceVolume $script:vhd $script:mount $script:guid
if (!$proof.file_backed -or !$proof.no_drive_letter -or !$proof.mount_verified) {throw 'VALID_VOLUME_REJECTED'}
$storageCases=0
foreach($case in @(@('IsBoot',$true),@('IsSystem',$true),@('BusType','NVMe'),@('Size',1000204886016),@('Location','C:\elsewhere.vhdx'))) {
  $saved=$script:disk.($case[0]);$script:disk.($case[0])=$case[1]
  try {Get-VerifiedVhdDisk $script:vhd;throw 'UNSAFE_DISK_ACCEPTED'}
  catch {if($_.Exception.Message -ne 'WORKSPACE_DISK_IDENTITY_MISMATCH'){throw}}
  $script:disk.($case[0])=$saved;$storageCases++
}
$script:volume.FileSystemType='RAW'
try {Get-VerifiedWorkspaceVolume $script:vhd $script:mount $script:guid;throw 'RAW_VOLUME_ACCEPTED'}
catch {if($_.Exception.Message -ne 'WORKSPACE_FILESYSTEM_NOT_VERIFIED'){throw}}
$script:volume.FileSystemType='NTFS';$script:partition.DriveLetter='D'
try {Get-VerifiedWorkspaceVolume $script:vhd $script:mount $script:guid;throw 'DRIVE_LETTER_ACCEPTED'}
catch {if($_.Exception.Message -ne 'WORKSPACE_UNEXPECTED_DRIVE_LETTER'){throw}}
$script:partition.DriveLetter=[char]0;$script:partition.AccessPaths+=,'D:\'
try {Get-VerifiedWorkspaceVolume $script:vhd $script:mount $script:guid;throw 'EXTRA_ACCESS_PATH_ACCEPTED'}
catch {if($_.Exception.Message -ne 'WORKSPACE_ACCESS_PATH_MISMATCH'){throw}}
$source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../deploy/windows/install-worker.ps1') -Raw
$resumeStart=$source.IndexOf('if ($ResumeServiceCreation) {')
$resumeEnd=$source.IndexOf('if (Get-Service -Name DevAIWorker -ErrorAction Ignore) { throw ''EXISTING_SERVICE')
$resume=$source.Substring($resumeStart,$resumeEnd-$resumeStart)
if($resume -match '(?i)(New-PrivateWorkspaceVolume|Format-Volume|Initialize-Disk|New-Partition|diskpart|Remove-Item)') {throw 'RESUME_CAN_MUTATE_STORAGE'}
if($resume.IndexOf('Assert-PartialWorkerInstall') -gt $resume.IndexOf('Copy-Item') -or
   $resume.IndexOf('if ($InspectInstall) { return }') -gt $resume.IndexOf('Copy-Item')) {throw 'RESUME_MUTATION_BEFORE_VALIDATION'}

# Exercise the complete read-only partial-install validator with real temporary
# files/manifests and mocked privileged ACL/storage/service inventory only.
$root=Join-Path ([IO.Path]::GetTempPath()) ('devai-partial-install-test-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
  $code=Join-Path $root 'code';$state=Join-Path $root 'state'
  $names=@('host-runtime/python.exe','sandbox-runtime/python.exe','sandbox-runtime/synthetic_process.py','control/worker_agent/windows_service.py','control/worker_agent/volume_host.py','control/worker_agent/workspace.py')
  $hashes=@{}
  foreach($name in $names) {
    $path=Join-Path $code $name
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    [IO.File]::WriteAllText($path,'non-secret code fixture')
    $hashes[$name]=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
  }
  foreach($name in @('credentials/worker.dpapi','volumes/workspace.vhdx','volumes/attach.txt')) {
    $path=Join-Path $state $name
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    [IO.File]::WriteAllText($path,'non-secret placeholder')
  }
  [IO.File]::WriteAllText((Join-Path $code 'manifest.json'),($hashes | ConvertTo-Json))
  $sid='S-1-5-80-1-2-3-4-5'
  # RH-B 5A-2A: the fixture is a TARGET artifact. A real one, with the real
  # recovered three-ACE ACL, is required -- a placeholder string can no longer
  # satisfy target-state validation.
  # No real ACL inspection is possible here: this harness stubs Get-Acl globally.
  $script:fixture=(Join-Path $env:USERPROFILE 'DevAIWorkerAccessProbe/service-access-denial.fixture')
  $config=@{worker_id=[Guid]::NewGuid().ToString();api_base_url='http://100.91.132.78:8765';service_sid=$sid;
    credential_path=(Join-Path $state 'credentials/worker.dpapi');sandbox_runtime=(Join-Path $code 'sandbox-runtime');
    personal_denial_fixture=$script:fixture;volume_guid=$script:guid;
    sandbox_executable_sha256=$hashes['sandbox-runtime/python.exe'];sandbox_payload_sha256=$hashes['sandbox-runtime/synthetic_process.py']}
  $cfg=Join-Path $state 'service.json'
  function Save-TestConfig {[IO.File]::WriteAllText($cfg,($config | ConvertTo-Json))}
  Save-TestConfig
    # RH-B 5A-2B: the release contract is manifest.json ONLY. The dual-shape seam
  # is gone, so the fixture is a real release manifest whose Files is a genuine
  # dictionary of {sha256,size} entries.
  $releaseFiles=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
  foreach($key in $hashes.Keys){
    $item=Get-Item -LiteralPath (Join-Path $code $key)
    $releaseFiles[$key]=[pscustomobject]@{sha256=[string]$hashes[$key];size=[long]$item.Length}
  }
  $releaseManifest=[pscustomobject]@{Files=$releaseFiles}
  $script:helper=[pscustomobject]@{State='Stopped';StartName='LocalSystem';PathName=((Get-WorkerServiceCommand $code $cfg)+' --volume-host')}
  function Get-Service {param($Name,$ErrorAction) return $null}
  $script:worker=[pscustomobject]@{State='Stopped';StartName='NT SERVICE\DevAIWorker';PathName=(Get-WorkerServiceCommand $code $cfg);StartMode='Auto'}
  function Get-CimInstance {param($ClassName,$Filter) if($Filter -eq "Name='DevAIWorker'"){return $script:worker};return $script:helper}
  function Assert-ManagedPrivateAcl {param($Path,$ServiceSid,[switch]$AllowInherited) Assert-ManagedNoReparse $Path | Out-Null}
  function sc.exe {$global:LASTEXITCODE=0;return $sid}
  $tokens=$null;$errors=$null
  $tokens=$null;$errors=$null
  $helperAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../deploy/windows/install-support.ps1'),[ref]$tokens,[ref]$errors)
  $entryFunction=$helperAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
  if ($null -eq $entryFunction) { throw 'SOURCE_ENTRY_VALIDATOR_MISSING' }
  . ([ScriptBlock]::Create($entryFunction.Extent.Text))
  $script:vhd=Join-Path $state 'volumes/workspace.vhdx';$script:mount=Join-Path $state 'workspace-volume'
  $script:image.ImagePath=$script:vhd;$script:disk.Location=$script:vhd
  $script:partition.AccessPaths=@(($script:mount+'\'),$script:guid)
  $result=Assert-PartialWorkerInstall $code $state $releaseManifest
  if(!$result.volume.mount_verified){throw 'VALID_PARTIAL_INSTALL_REJECTED'}
  # OLD: a worker_id differing from package.worker_id was rejected. That
  # comparison is GONE BY DESIGN -- the release manifest no longer owns any
  # target value. NEW: worker_id is validated against TARGET POLICY (UUID).
  # WHY_NOT_WEAKER: the old check only detected a mismatch with a removed
  # field; the new check rejects any structurally invalid identity outright, so
  # it accepts strictly fewer bad states.
  $originalWorker=$config.worker_id;$config.worker_id='not-a-uuid';Save-TestConfig
  try{Assert-PartialWorkerInstall $code $state $releaseManifest;throw 'INVALID_WORKER_ID_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PARTIAL_INSTALL_CONFIG_MISMATCH'){throw}}
  # A structurally valid but different UUID is now legitimately accepted:
  # identity is target state, not package state.
  $config.worker_id=[Guid]::NewGuid().ToString();Save-TestConfig
  Assert-PartialWorkerInstall $code $state $releaseManifest | Out-Null
  # api_base_url outside the preserved 18-case policy must still fail closed.
  $config.api_base_url='https://10.0.0.1/';Save-TestConfig
  try{Assert-PartialWorkerInstall $code $state $releaseManifest;throw 'RFC1918_API_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PARTIAL_INSTALL_CONFIG_MISMATCH'){throw}}
  $config.api_base_url='http://100.91.132.78:8765';Save-TestConfig
  # The denial fixture must still be a genuine witness: a relative path is not.
  $config.personal_denial_fixture='relative-probe';Save-TestConfig
  try{Assert-PartialWorkerInstall $code $state $releaseManifest;throw 'BAD_FIXTURE_PATH_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'INVALID_PERSONAL_FIXTURE_PATH'){throw}}
  $config.personal_denial_fixture=$script:fixture;Save-TestConfig
  $script:helper.State='Running'
  try{Assert-PartialWorkerInstall $code $state $releaseManifest;throw 'RUNNING_HELPER_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PARTIAL_INSTALL_HELPER_MISMATCH'){throw}}
  $script:helper.State='Stopped'
  # Existing-service diagnostics accept ONLY the pinned old/new service source.
  # Any other runtime mismatch or administrative service identity stays closed.
  $oldService=$hashes['control/worker_agent/windows_service.py']
  $releaseFiles['control/worker_agent/windows_service.py'].sha256='a'*64
  $script:helper.State='Running'
  Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $oldService | Out-Null
  try{Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash ('b'*64);throw 'UNKNOWN_SERVICE_HASH_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'DIAGNOSTIC_PACKAGE_RUNTIME_MISMATCH'){throw}}
  $script:worker.StartName='LocalSystem'
  try{Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $oldService;throw 'ADMIN_WORKER_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'DIAGNOSTIC_WORKER_SERVICE_MISMATCH'){throw}}
  $script:worker.StartName='NT SERVICE\DevAIWorker'
  $releaseFiles['sandbox-runtime/python.exe'].sha256='c'*64
  try{Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $oldService;throw 'UNRELATED_RUNTIME_UPGRADE_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'DIAGNOSTIC_PACKAGE_RUNTIME_MISMATCH'){throw}}
  $releaseFiles['sandbox-runtime/python.exe'].sha256=$hashes['sandbox-runtime/python.exe']
  $oldWorkspace=$hashes['control/worker_agent/workspace.py']
  $releaseFiles['control/worker_agent/workspace.py'].sha256='d'*64
  Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $oldService -PreviousWorkspaceHash $oldWorkspace | Out-Null
  try{Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $oldService -PreviousWorkspaceHash ('e'*64);throw 'UNKNOWN_WORKSPACE_HASH_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'DIAGNOSTIC_PACKAGE_RUNTIME_MISMATCH'){throw}}
  try{Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $oldService;throw 'WORKSPACE_UPDATE_WITHOUT_PIN_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'DIAGNOSTIC_PACKAGE_RUNTIME_MISMATCH'){throw}}
  $releaseFiles['control/worker_agent/workspace.py'].sha256=$oldWorkspace
  $releaseFiles['control/worker_agent/windows_service.py'].sha256=$oldService
  $script:helper.State='Stopped'
  [IO.File]::WriteAllText((Join-Path $code 'host-runtime/python.exe'),'altered code')
  try{Assert-PartialWorkerInstall $code $state $releaseManifest;throw 'TAMPERED_RUNTIME_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'INSTALLED_RUNTIME_INTEGRITY_FAILED'){throw}}
} finally {
  if([IO.Path]::GetDirectoryName($root) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($root,$true)
}
function Test-Path {param($LiteralPath) return $true}
try {New-PrivateWorkspaceVolume $script:vhd $script:mount;throw 'EXISTING_IMAGE_CAN_BE_FORMATTED'}
catch {if($_.Exception.Message -ne 'WORKSPACE_IMAGE_ALREADY_EXISTS'){throw}}
Write-Output (@{passed=$true;service_quoting=$true;virtual_account=$true;storage_rejection_cases=$storageCases+3;resume_no_format=$true} | ConvertTo-Json -Compress)
