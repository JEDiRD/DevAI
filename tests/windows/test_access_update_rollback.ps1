$ErrorActionPreference='Stop'
# The extracted transaction calls the REAL release-digest helper, so the
# authoritative implementation is loaded rather than a local reimplementation.
$path=Join-Path $PSScriptRoot '../../deploy/windows/update-worker-access-diagnostic.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
. (Join-Path $PSScriptRoot '../../deploy/windows/install-support.ps1')
if($errors.Count){throw 'UPDATE_SYNTAX_INVALID'}
$blocks=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and
  $node.Extent.Text.Contains('ACCESS_DIAGNOSTIC_UPDATE_INTEGRITY_FAILED') -and
  $node.Extent.Text.Contains('ACCESS_DIAGNOSTIC_UPDATE_ROLLED_BACK')},$true))
if($blocks.Count -ne 1){throw 'UPDATE_TRANSACTION_NOT_FOUND'}
$transaction=[ScriptBlock]::Create($blocks[0].Extent.Text)
# Exercise real file/hash/ACL operations ONLY in an owned test directory.
# Every SCM/security-policy call in this extracted transaction is mocked.
function Get-CimInstance {param($ClassName,$Filter) return [pscustomobject]@{State='Stopped';ProcessId=0}}
function Get-Service {param($Name) return [pscustomobject]@{Status='Stopped'}}
function Stop-Service {throw 'UNEXPECTED_SERVICE_MUTATION'}
function Assert-ManagedPrivateAcl {param($Path,$Sid,[switch]$AllowInherited) if(!(Test-Path -LiteralPath $Path)){throw 'TEST_MANIFEST_MISSING'}}

# The ONLY security-descriptor control bit this comparison may ignore is
# SE_DACL_AUTO_INHERITED (ControlFlags.DiscretionaryAclAutoInherited, rendered
# "AI"). Windows sets it when Set-Acl writes a descriptor over an
# auto-inherited parent. It is advisory: it grants no access and revokes none.
# Every other control bit, and every other descriptor field, is compared.
$script:AutoInheritedBit=[Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited

function Get-AclStructure([string]$Path) {
  $acl=Get-Acl -LiteralPath $Path
  # Parse the descriptor structurally instead of reading rendered SDDL text.
  $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
  $aces=@()
  foreach($r in $acl.Access) {
    $aces+=[pscustomobject]@{
      Sid=$r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      Type=[string]$r.AccessControlType
      Rights=[int]$r.FileSystemRights
      Inheritance=[string]$r.InheritanceFlags
      Propagation=[string]$r.PropagationFlags
      Inherited=[bool]$r.IsInherited
    }
  }
  return [pscustomobject]@{
    Path=$Path
    Owner=$(if($raw.Owner){$raw.Owner.Value}else{'<absent>'})
    Group=$(if($raw.Group){$raw.Group.Value}else{'<absent>'})
    HasDacl=[bool]$raw.DiscretionaryAcl
    Protected=[bool]$acl.AreAccessRulesProtected
    ControlFlags=[string]$raw.ControlFlags
    ControlFlagsMasked=[string]($raw.ControlFlags -band (-bnot $script:AutoInheritedBit))
    AceCount=$aces.Count
    Aces=$aces
  }
}

function Get-AceProjection($Structure) {
  return @($Structure.Aces | ForEach-Object {
    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.Sid,$_.Type,$_.Rights,$_.Inheritance,$_.Propagation,$_.Inherited
  } | Sort-Object)
}

# Returns $null when the two structures are security-equivalent, otherwise a
# short reason naming the FIRST field that differs.
function Compare-AclStructure($Before,$After,[string]$Label) {
  if($Before.Owner -cne $After.Owner){return "$Label OWNER_CHANGED:$($Before.Owner)->$($After.Owner)"}
  if($Before.Group -cne $After.Group){return "$Label GROUP_CHANGED:$($Before.Group)->$($After.Group)"}
  if($Before.HasDacl -ne $After.HasDacl){return "$Label DACL_PRESENCE_CHANGED"}
  if($Before.Protected -ne $After.Protected){return "$Label DACL_PROTECTION_CHANGED"}
  if($Before.ControlFlagsMasked -cne $After.ControlFlagsMasked){return "$Label CONTROL_FLAGS_CHANGED:$($Before.ControlFlags)->$($After.ControlFlags)"}
  if($Before.AceCount -ne $After.AceCount){return "$Label ACE_COUNT_CHANGED:$($Before.AceCount)->$($After.AceCount)"}
  $beforeProjection=((Get-AceProjection $Before) -join "`n")
  $afterProjection=((Get-AceProjection $After) -join "`n")
  if($beforeProjection -cne $afterProjection){return "$Label ACE_SET_CHANGED"}
  return $null
}

$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-update-rollback-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
$canariesRun=0
try {
  foreach($fail in @($false,$true)) {
    $fixture=Join-Path $temp ([Guid]::NewGuid().ToString('N'))
    $PackageRoot=Join-Path $fixture 'package'
    $code=Join-Path $fixture 'installed'
    $backup=Join-Path $fixture 'backup'
    foreach($directory in @((Join-Path $PackageRoot 'control/worker_agent'),(Join-Path $code 'control/worker_agent'),$backup)){[IO.Directory]::CreateDirectory($directory) | Out-Null}
    $manifest=[pscustomobject]@{};$files=[pscustomobject]@{};$targets=@()
    foreach($name in @('workspace.py','windows_service.py')) {
      $relative='control/worker_agent/'+$name
      # The installed target MUST live at the same package-relative path the
      # real transaction uses. Placing it elsewhere made every "clean" run fail
      # internally and roll back, so the ACL preservation gate was never
      # actually exercised against a successful update.
      $target=Join-Path $code $relative;$source=Join-Path $PackageRoot $relative
      [IO.File]::WriteAllText($target,'original-'+$name)
      [IO.File]::WriteAllText($source,'updated-'+$name)
      $manifest | Add-Member -NotePropertyName $relative -NotePropertyValue ((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant())
      $digest=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant()
      if($fail -and $name -eq 'windows_service.py'){$digest='a'*64}
      $files | Add-Member -NotePropertyName $relative -NotePropertyValue $digest
      # 'acl' is the raw descriptor the extracted transaction re-applies with
      # Set-Acl; 'before' is this test's own structural snapshot. The extracted
      # block consumes the harness's own $targets, so both keys must be present.
      $targets+=@{name=$name;relative=$relative;path=$target;acl=(Get-Acl -LiteralPath $target);before=(Get-AclStructure $target)}
      Copy-Item -LiteralPath $target -Destination (Join-Path $backup $name)
    }
    $manifestFile=Join-Path $code 'manifest.json'
    [IO.File]::WriteAllText($manifestFile,($manifest | ConvertTo-Json))
    Copy-Item -LiteralPath $manifestFile -Destination (Join-Path $backup 'manifest.json')
    # RH-B 5A-2B: the extracted transaction reads release digests from a
    # validated manifest.json shape, not from a package.json-shaped object.
    $releaseFiles=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($prop in $files.PSObject.Properties){
      $releaseFiles[$prop.Name]=[pscustomobject]@{sha256=[string]$prop.Value;size=0}
    }
    $releaseManifest=[pscustomobject]@{Files=$releaseFiles}
    $verified=@{manifest=$manifest;manifest_file=$manifestFile;config=@{service_sid='test-public-sid'}}
    if($fail) {
      try {& $transaction;throw 'CORRUPT_UPDATE_ACCEPTED'}
      catch {if($_.Exception.Message -ne 'ACCESS_DIAGNOSTIC_UPDATE_ROLLED_BACK'){throw}}
      foreach($target in $targets) {
        if((Get-FileHash -LiteralPath $target.path).Hash -cne (Get-FileHash -LiteralPath (Join-Path $backup $target.name)).Hash){throw 'SOURCE_ROLLBACK_FAILED'}
      }
      if((Get-FileHash -LiteralPath $manifestFile).Hash -cne (Get-FileHash -LiteralPath (Join-Path $backup 'manifest.json')).Hash){throw 'MANIFEST_ROLLBACK_FAILED'}
    } else {
      & $transaction
      $after=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
      foreach($target in $targets) {
        if($after.PSObject.Properties[$target.relative].Value -cne (Get-FileHash -LiteralPath $target.path).Hash.ToLowerInvariant()){throw 'UPDATED_MANIFEST_HASH_WRONG'}
      }
    }
    # ---- the preservation gate -------------------------------------------
    foreach($target in $targets) {
      $now=Get-AclStructure $target.path
      $reason=Compare-AclStructure $target.before $now 'UPDATED_FILE'
      if($reason){
        # Emit the structural evidence so a failure is diagnosable without
        # re-running under a debugger.
        Write-Host ("ACL_DRIFT owner $($target.before.Owner)->$($now.Owner) group $($target.before.Group)->$($now.Group) protected $($target.before.Protected)->$($now.Protected)")
        Write-Host ("ACL_DRIFT flags '$($target.before.ControlFlags)'->'$($now.ControlFlags)' masked '$($target.before.ControlFlagsMasked)'->'$($now.ControlFlagsMasked)'")
        Write-Host 'ACL_DRIFT_BEFORE_ACES'
        Get-AceProjection $target.before | ForEach-Object { Write-Host("  BEFORE $_") }
        Write-Host 'ACL_DRIFT_AFTER_ACES'
        Get-AceProjection $now | ForEach-Object { Write-Host("  AFTER  $_") }
        throw $reason
      }
      Write-Host ("ACL_PRESERVED owner=$($now.Owner) group=$($now.Group) protected=$($now.Protected) flags=$($now.ControlFlags) aces=$($now.AceCount)")
    }
  }

  # ---- mutation canaries --------------------------------------------------
  # Each canary mutates ONE security-descriptor property and requires the
  # comparator to reject it for the intended reason. Without these, a weakened
  # comparator could pass silently.
  $canaryFile=Join-Path $code 'canary.txt'
  [IO.File]::WriteAllText($canaryFile,'canary')
  $base=Get-AclStructure $canaryFile

  function Copy-Structure($S) {
    return [pscustomobject]@{
      Owner=$S.Owner; Group=$S.Group; HasDacl=$S.HasDacl; Protected=$S.Protected
      ControlFlags=$S.ControlFlags; ControlFlagsMasked=$S.ControlFlagsMasked
      AceCount=$S.AceCount
      Aces=@($S.Aces | ForEach-Object {
        [pscustomobject]@{Sid=$_.Sid;Type=$_.Type;Rights=$_.Rights;Inheritance=$_.Inheritance;Propagation=$_.Propagation;Inherited=$_.Inherited}})
    }
  }
  function Expect-CanaryDetected([string]$Name,[scriptblock]$Mutate,[string]$Expected) {
    $mutated=Copy-Structure $base
    & $Mutate $mutated
    $reason=Compare-AclStructure $base $mutated 'CANARY'
    if(!$reason){throw "ACL_CANARY_NOT_DETECTED:$Name"}
    if($reason -notlike "*$Expected*"){throw "ACL_CANARY_WRONG_REASON:$Name got=$reason want=$Expected"}
    Write-Host ("ACL_CANARY_DETECTED {0,-22} {1}" -f $Name,$reason)
    $script:canariesRun++
  }

  Expect-CanaryDetected 'owner'            {param($m) $m.Owner='S-1-5-18'} 'OWNER_CHANGED'
  Expect-CanaryDetected 'group'            {param($m) $m.Group='S-1-5-18'} 'GROUP_CHANGED'
  Expect-CanaryDetected 'dacl_protection'  {param($m) $m.Protected=(-not $m.Protected)} 'DACL_PROTECTION_CHANGED'
  Expect-CanaryDetected 'dacl_presence'    {param($m) $m.HasDacl=(-not $m.HasDacl)} 'DACL_PRESENCE_CHANGED'
  Expect-CanaryDetected 'unauthorized_control_flag' {
    param($m) $m.ControlFlagsMasked=[string]([Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
  } 'CONTROL_FLAGS_CHANGED'
  Expect-CanaryDetected 'ace_rights'       {param($m) $m.Aces[0].Rights=($m.Aces[0].Rights -band (-bnot 32))} 'ACE_SET_CHANGED'
  Expect-CanaryDetected 'ace_allow_to_deny' {param($m) $m.Aces[0].Type='Deny'} 'ACE_SET_CHANGED'
  Expect-CanaryDetected 'ace_inheritance'  {param($m) $m.Aces[0].Inheritance='ContainerInherit'} 'ACE_SET_CHANGED'
  Expect-CanaryDetected 'ace_propagation'  {param($m) $m.Aces[0].Propagation='InheritOnly'} 'ACE_SET_CHANGED'
  Expect-CanaryDetected 'ace_extra' {
    param($m) $m.Aces=@($m.Aces)+@([pscustomobject]@{Sid='S-1-1-0';Type='Allow';Rights=1;Inheritance='None';Propagation='None';Inherited=$false}); $m.AceCount=$m.AceCount+1
  } 'ACE_COUNT_CHANGED'

  # Real on-disk Everyone grant must also be rejected, not merely a synthetic
  # structure. This is the closest analogue of a real ACL-broadening bug.
  $everyone=New-Object Security.AccessControl.FileSystemAccessRule(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Read','None','None','Allow')
  $widened=Get-Acl -LiteralPath $canaryFile
  $widened.AddAccessRule($everyone)
  Set-Acl -LiteralPath $canaryFile -AclObject $widened
  $reason=Compare-AclStructure $base (Get-AclStructure $canaryFile) 'CANARY'
  if(!$reason){throw 'ACL_CANARY_NOT_DETECTED:everyone_read'}
  if($reason -notlike '*ACE_COUNT_CHANGED*' -and $reason -notlike '*ACE_SET_CHANGED*'){throw "ACL_CANARY_WRONG_REASON:everyone_read got=$reason"}
  Write-Host ("ACL_CANARY_DETECTED {0,-22} {1}" -f 'everyone_read',$reason)
  $canariesRun++
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
Write-Host ("ACCESS_UPDATE_AND_ROLLBACK_PASSED canaries=$canariesRun")