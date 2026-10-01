$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '../../deploy/windows/update-worker-access-diagnostic.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
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
    $package=@{files=$files}
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
    foreach($target in $targets) {
      if((Get-Acl -LiteralPath $target.path).Sddl -cne $target.acl.Sddl){throw 'UPDATED_FILE_ACL_CHANGED'}
    }
  }
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
Write-Output 'ACCESS_UPDATE_AND_ROLLBACK_PASSED'
