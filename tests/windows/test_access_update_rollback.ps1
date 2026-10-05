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
$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-update-rollback-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
  foreach($fail in @($false,$true)) {
    $fixture=Join-Path $temp ([Guid]::NewGuid().ToString('N'))
    $PackageRoot=Join-Path $fixture 'package'
    $code=Join-Path $fixture 'installed'
    $backup=Join-Path $fixture 'backup'
    foreach($directory in @((Join-Path $PackageRoot 'control/worker_agent'),$code,$backup)){[IO.Directory]::CreateDirectory($directory) | Out-Null}
    $manifest=[pscustomobject]@{};$files=[pscustomobject]@{};$targets=@()
    foreach($name in @('workspace.py','windows_service.py')) {
      $relative='control/worker_agent/'+$name
      $target=Join-Path $code $name;$source=Join-Path $PackageRoot $relative
      [IO.File]::WriteAllText($target,'original-'+$name)
      [IO.File]::WriteAllText($source,'updated-'+$name)
      $manifest | Add-Member -NotePropertyName $relative -NotePropertyValue ((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant())
      $digest=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant()
      if($fail -and $name -eq 'windows_service.py'){$digest='a'*64}
      $files | Add-Member -NotePropertyName $relative -NotePropertyValue $digest
      $targets+=@{name=$name;relative=$relative;path=$target;acl=(Get-Acl -LiteralPath $target)}
      Copy-Item -LiteralPath $target -Destination (Join-Path $backup $name)
    }
    $manifestFile=Join-Path $code 'manifest.json'
    [IO.File]::WriteAllText($manifestFile,($manifest | ConvertTo-Json))
    Copy-Item -LiteralPath $manifestFile -Destination (Join-Path $backup 'manifest.json')
    $verified=@{manifest=$manifest;manifest_file=$manifestFile;config=@{service_sid='test-public-sid'}}
    # RH-B 5A-2B: the extracted transaction reads release digests from a
    # validated manifest.json shape, not from a package.json-shaped object.
    $releaseFiles=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach($prop in $files.PSObject.Properties){
      $releaseFiles[$prop.Name]=[pscustomobject]@{sha256=[string]$prop.Value;size=0}
    }
    $releaseManifest=[pscustomobject]@{Files=$releaseFiles}
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
    # ACL preservation is asserted STRUCTURALLY, not by comparing the whole SDDL
    # string. SDDL also encodes the DACL control flags, including
    # SE_DACL_AUTO_INHERITED ("AI"), which Windows sets when a descriptor is
    # written over an auto-inherited parent. That bit is an advisory
    # auto-inheritance hint: it grants no access and revokes none, and the OS
    # sets it even when the update faithfully re-applies the captured
    # descriptor. Comparing it asserts a Windows write-path detail rather than a
    # security property, and it failed on a correct implementation under an
    # elevated token.
    #
    # This assertion is not weaker than the product contract. It pins every
    # security-relevant field the product actually relies on, and more: owner
    # SID, DACL protection state, and for each ACE the SID, access type, the
    # exact FileSystemRights mask, inheritance flags, propagation flags and
    # IsInherited. Any broadening (a new principal such as Everyone, Users,
    # Authenticated Users or the service SID), any rights change, any
    # protection change and any owner change still fails here.
    foreach($target in $targets) {
      $beforeAcl=$target.acl
      $afterAcl=Get-Acl -LiteralPath $target.path
      $beforeOwner=([Security.Principal.NTAccount]$beforeAcl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
      $afterOwner=([Security.Principal.NTAccount]$afterAcl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
      if($beforeOwner -ne $afterOwner){throw 'UPDATED_FILE_ACL_OWNER_CHANGED'}
      if($beforeAcl.AreAccessRulesProtected -ne $afterAcl.AreAccessRulesProtected){throw 'UPDATED_FILE_ACL_PROTECTION_CHANGED'}
      $describe={param($rule) (
        $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value + '|' +
        [string]$rule.AccessControlType + '|' +
        [int]$rule.FileSystemRights + '|' +
        [string]$rule.InheritanceFlags + '|' +
        [string]$rule.PropagationFlags + '|' +
        [string]$rule.IsInherited)}
      $beforeRules=@($beforeAcl.Access | ForEach-Object { & $describe $_ } | Sort-Object)
      $afterRules=@($afterAcl.Access  | ForEach-Object { & $describe $_ } | Sort-Object)
      if(($beforeRules -join "`n") -cne ($afterRules -join "`n")){throw 'UPDATED_FILE_ACL_CHANGED'}
    }
    # The structural assertion must still have teeth. Deliberately broaden ONE
    # file's ACL the way a real regression would (grant Everyone read) and
    # require the comparison above to detect it. Without this, a weakened
    # assertion could pass silently.
    $canary=$targets[0].path
    $canaryBefore=Get-Acl -LiteralPath $canary
    $canaryRules=@($canaryBefore.Access | ForEach-Object { & $describe $_ } | Sort-Object)
    $broadened=Get-Acl -LiteralPath $canary
    $broadened.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
      [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Read','None','None','Allow')))
    Set-Acl -LiteralPath $canary -AclObject $broadened
    $canaryAfter=Get-Acl -LiteralPath $canary
    $canaryAfterRules=@($canaryAfter.Access | ForEach-Object { & $describe $_ } | Sort-Object)
    if(($canaryRules -join "`n") -ceq ($canaryAfterRules -join "`n")){throw 'ACL_ASSERTION_HAS_NO_TEETH'}
    Set-Acl -LiteralPath $canary -AclObject $canaryBefore
  }
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
Write-Output 'ACCESS_UPDATE_AND_ROLLBACK_PASSED'
