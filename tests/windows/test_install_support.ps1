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
  $names=@('host-runtime/python.exe','sandbox-runtime/python.exe','sandbox-runtime/synthetic_process.py','control/worker_agent/windows_service.py','control/worker_agent/volume_host.py')
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
  $config=@{worker_id=[Guid]::NewGuid().ToString();api_base_url='http://100.91.132.78:8765';service_sid=$sid;
    credential_path=(Join-Path $state 'credentials/worker.dpapi');sandbox_runtime=(Join-Path $code 'sandbox-runtime');
    personal_denial_fixture='non-secret probe';volume_guid=$script:guid;
    sandbox_executable_sha256=$hashes['sandbox-runtime/python.exe'];sandbox_payload_sha256=$hashes['sandbox-runtime/synthetic_process.py']}
  $cfg=Join-Path $state 'service.json'
  function Save-TestConfig {[IO.File]::WriteAllText($cfg,($config | ConvertTo-Json))}
  Save-TestConfig
  $package=[pscustomobject]@{worker_id=$config.worker_id;api_base_url=$config.api_base_url;personal_denial_fixture=$config.personal_denial_fixture;files=($hashes | ConvertTo-Json | ConvertFrom-Json)}
  $script:helper=[pscustomobject]@{State='Stopped';StartName='LocalSystem';PathName=((Get-WorkerServiceCommand $code $cfg)+' --volume-host')}
  function Get-Service {param($Name,$ErrorAction) return $null}
  function Get-CimInstance {param($ClassName,$Filter) return $script:helper}
  function Assert-ManagedPrivateAcl {param($Path,$ServiceSid) Assert-ManagedNoReparse $Path | Out-Null}
  function sc.exe {$global:LASTEXITCODE=0;return $sid}
  $tokens=$null;$errors=$null
  $installerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../deploy/windows/install-worker.ps1'),[ref]$tokens,[ref]$errors)
  $entryFunction=$installerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
  . ([ScriptBlock]::Create($entryFunction.Extent.Text))
  $script:vhd=Join-Path $state 'volumes/workspace.vhdx';$script:mount=Join-Path $state 'workspace-volume'
  $script:image.ImagePath=$script:vhd;$script:disk.Location=$script:vhd
  $script:partition.AccessPaths=@(($script:mount+'\'),$script:guid)
  $result=Assert-PartialWorkerInstall $code $state $package
  if(!$result.volume.mount_verified){throw 'VALID_PARTIAL_INSTALL_REJECTED'}
  $originalWorker=$config.worker_id;$config.worker_id=[Guid]::NewGuid().ToString();Save-TestConfig
  try{Assert-PartialWorkerInstall $code $state $package;throw 'FOREIGN_WORKER_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PARTIAL_INSTALL_CONFIG_MISMATCH'){throw}}
  $config.worker_id=$originalWorker;Save-TestConfig
  $script:helper.State='Running'
  try{Assert-PartialWorkerInstall $code $state $package;throw 'RUNNING_HELPER_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PARTIAL_INSTALL_HELPER_MISMATCH'){throw}}
  $script:helper.State='Stopped'
  [IO.File]::WriteAllText((Join-Path $code 'host-runtime/python.exe'),'altered code')
  try{Assert-PartialWorkerInstall $code $state $package;throw 'TAMPERED_RUNTIME_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'INSTALLED_RUNTIME_INTEGRITY_FAILED'){throw}}
} finally {
  if([IO.Path]::GetDirectoryName($root) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($root,$true)
}
function Test-Path {param($LiteralPath) return $true}
try {New-PrivateWorkspaceVolume $script:vhd $script:mount;throw 'EXISTING_IMAGE_CAN_BE_FORMATTED'}
catch {if($_.Exception.Message -ne 'WORKSPACE_IMAGE_ALREADY_EXISTS'){throw}}
Write-Output (@{passed=$true;service_quoting=$true;virtual_account=$true;storage_rejection_cases=$storageCases+3;resume_no_format=$true} | ConvertTo-Json -Compress)
