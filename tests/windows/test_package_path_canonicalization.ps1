# Real-filesystem regression for canonical package-member path derivation.
#
# Defect (proven on canonical windows-2025 CI): install-support.ps1 derived a
# member's manifest-relative path by subtracting the length of the
# caller-supplied package root from the enumerated FullName. That assumed both
# used the same lexical spelling. When the root is reached through an 8.3 alias
# the canonical runner exposes TEMP as C:\Users\RUNNER~1\..., the offset is
# wrong and a byte-for-byte VALID package is rejected as UNMANIFESTED_PACKAGE_FILE.
#
# This harness exercises a REAL filesystem alias. It never mocks path strings
# and never hardcodes RUNNER~1: the short alias is discovered dynamically, and
# hosts without 8.3 generation report an environment limitation instead of a
# false pass.
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$support = Join-Path $repoRoot 'deploy\windows\install-support.ps1'
. $support

$results = New-Object System.Collections.ArrayList
function Record([string]$name, [bool]$ok, [string]$detail = '') {
  [void]$results.Add([pscustomobject]@{ name = $name; ok = $ok; detail = $detail })
}

function New-Tree([string]$root) {
  New-Item -ItemType Directory -Force -Path (Join-Path $root 'control\worker_agent') | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $root 'host-runtime') | Out-Null
  [IO.File]::WriteAllText((Join-Path $root 'install-worker.ps1'), "# installer`n")
  [IO.File]::WriteAllText((Join-Path $root 'install-support.ps1'), "# support`n")
  [IO.File]::WriteAllText((Join-Path $root 'manifest.json'), "{}")
  [IO.File]::WriteAllText((Join-Path $root 'control\worker_agent\windows_service.py'), "# svc`n")
  [IO.File]::WriteAllText((Join-Path $root 'control\worker_agent\provision.py'), "# prov`n")
  [IO.File]::WriteAllText((Join-Path $root 'host-runtime\python.exe'), "MZfake")
}

$fso = New-Object -ComObject Scripting.FileSystemObject
$base = Join-Path ([IO.Path]::GetTempPath()) ('canon_' + [guid]::NewGuid().ToString('N').Substring(0, 10))
New-Item -ItemType Directory -Force -Path $base | Out-Null
try {
  $folder = $fso.GetFolder($base)
  # FileSystemObject.Path is the long form; LongPath is not populated
  # consistently across hosts, so fall back to it only when non-empty.
  $longRoot = $folder.Path
  if ([string]::IsNullOrWhiteSpace($longRoot)) { $longRoot = $folder.LongPath }
  $longRoot = $longRoot.TrimEnd('\')
  $shortRoot = $folder.ShortPath
  if ($null -ne $shortRoot) { $shortRoot = $shortRoot.TrimEnd('\') }
  $shortAvailable = ($shortRoot -ne $longRoot) -and (Test-Path -LiteralPath $shortRoot)

  Record 'ALIAS_DISCOVERED_DYNAMICALLY' $true "long=$longRoot short=$shortRoot"
  Record 'SHORT_ALIAS_AVAILABLE' $shortAvailable $(if ($shortAvailable) { '8.3 generation enabled' } else { 'ENVIRONMENT_LIMITATION: 8.3 name generation unavailable on this host' })

  New-Tree $base

  # ---- the same tree, addressed through both spellings ------------------
  $memberRel = 'control/worker_agent/windows_service.py'
  $viaLong = Get-CanonicalPackageRelativePath -PackageRoot $longRoot -CandidatePath (Join-Path $base $memberRel.Replace('/', '\'))
  Record 'LONG_ROOT_RELATIVE_DERIVED' ($viaLong -eq $memberRel) "got=$viaLong"

  if ($shortAvailable) {
    $viaShort = Get-CanonicalPackageRelativePath -PackageRoot $shortRoot -CandidatePath (Join-Path $base $memberRel.Replace('/', '\'))
    Record 'SHORT_ROOT_RELATIVE_DERIVED' ($viaShort -eq $memberRel) "got=$viaShort"
    Record 'RELATIVE_MEMBER_SET_MATCH' ($viaLong -eq $viaShort) "long=$viaLong short=$viaShort"

    # every enumerated member must agree across both spellings
    $setLong = @{}
    Get-ChildItem -LiteralPath $longRoot -Recurse -Force -File | ForEach-Object {
      $setLong[(Get-CanonicalPackageRelativePath -PackageRoot $longRoot -CandidatePath $_.FullName)] = $true
    }
    $setShort = @{}
    Get-ChildItem -LiteralPath $shortRoot -Recurse -Force -File | ForEach-Object {
      $setShort[(Get-CanonicalPackageRelativePath -PackageRoot $shortRoot -CandidatePath $_.FullName)] = $true
    }
    $joinedLong = (($setLong.Keys | Sort-Object) -join '|')
    $joinedShort = (($setShort.Keys | Sort-Object) -join '|')
    Record 'FULL_MEMBER_SET_MATCH' ($joinedLong -eq $joinedShort) `
      ("long=" + $setLong.Count + " short=" + $setShort.Count)
  }

  # ---- case-only spelling is Windows semantics, not a new member -------
  $caseRoot = $longRoot.ToUpperInvariant()
  if (Test-Path -LiteralPath $caseRoot) {
    $viaCase = Get-CanonicalPackageRelativePath -PackageRoot $caseRoot -CandidatePath (Join-Path $base $memberRel.Replace('/', '\'))
    Record 'CASE_ONLY_ROOT_SPELLING' ($viaCase -eq $memberRel) "got=$viaCase"
  } else {
    Record 'CASE_ONLY_ROOT_SPELLING' $true 'ENVIRONMENT_LIMITATION: upper-cased root not resolvable here'
  }

  # ---- §7 negatives ----------------------------------------------------
  $sibling = $base + '_sibling'
  New-Item -ItemType Directory -Force -Path $sibling | Out-Null
  [IO.File]::WriteAllText((Join-Path $sibling 'evil.txt'), 'x')
  try {
    $null = Get-CanonicalPackageRelativePath -PackageRoot $base -CandidatePath (Join-Path $sibling 'evil.txt')
    Record 'NEGATIVE_SIBLING_PREFIX_REJECTED' $false 'sibling prefix was accepted'
  } catch {
    Record 'NEGATIVE_SIBLING_PREFIX_REJECTED' ($_.Exception.Message -like 'PACKAGE_MEMBER_OUTSIDE_ROOT*') $_.Exception.Message
  }

  try {
    $null = Get-CanonicalPackageRelativePath -PackageRoot $base -CandidatePath $base
    Record 'NEGATIVE_ROOT_ITSELF_REJECTED' $false 'package root itself was accepted'
  } catch {
    Record 'NEGATIVE_ROOT_ITSELF_REJECTED' ($_.Exception.Message -like 'PACKAGE_MEMBER_IS_ROOT*') $_.Exception.Message
  }

  # outside-root canonical path (a real existing path elsewhere on the volume)
  $outside = Join-Path ([IO.Path]::GetTempPath()) ('outside_' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
  [IO.File]::WriteAllText($outside, 'x')
  try {
    $null = Get-CanonicalPackageRelativePath -PackageRoot $base -CandidatePath $outside
    Record 'NEGATIVE_OUTSIDE_ROOT_REJECTED' $false 'outside path was accepted'
  } catch {
    Record 'NEGATIVE_OUTSIDE_ROOT_REJECTED' ($_.Exception.Message -like 'PACKAGE_MEMBER_OUTSIDE_ROOT*') $_.Exception.Message
  } finally {
    Remove-Item -LiteralPath $outside -Force -ErrorAction SilentlyContinue
  }

  # traversal, absolute and drive-qualified forms never reach the helper as
  # members, but assert the helper rejects them if they ever did
  foreach ($bad in @('..\evil.txt', 'C:\evil.txt', 'sub\..\..\evil.txt')) {
    $joined = Join-Path $base $bad
    try {
      $null = Get-CanonicalPackageRelativePath -PackageRoot $base -CandidatePath $joined
      Record ("NEGATIVE_REJECTED[$bad]") $false 'accepted'
    } catch {
      Record ("NEGATIVE_REJECTED[$bad]") $true $_.Exception.Message
    }
  }

  # unresolvable path must fail closed rather than pass through
  try {
    $null = Get-CanonicalPackageRelativePath -PackageRoot $base -CandidatePath (Join-Path $base 'does-not-exist.txt')
    Record 'NEGATIVE_UNRESOLVABLE_FAILS_CLOSED' $false 'accepted a nonexistent path'
  } catch {
    Record 'NEGATIVE_UNRESOLVABLE_FAILS_CLOSED' ($_.Exception.Message -like 'PACKAGE_PATH_CANONICALIZATION_FAILED*') $_.Exception.Message
  }

  Remove-Item -LiteralPath $sibling -Recurse -Force -ErrorAction SilentlyContinue
}
finally {
  Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object { -not $_.ok })
foreach ($r in $results) {
  Write-Host ("{0} {1,-42} {2}" -f $(if ($r.ok) { 'PASS ' } else { 'FAIL ' }), $r.name, $r.detail)
}
Write-Host ("CANONICALIZATION total={0} failed={1} short_alias={2}" -f $results.Count, $failed.Count, $shortAvailable)
if ($failed.Count -ne 0) { Write-Host 'PACKAGE_PATH_CANONICALIZATION_FAILED'; exit 1 }
Write-Host 'PACKAGE_PATH_CANONICALIZATION_PASSED'
exit 0