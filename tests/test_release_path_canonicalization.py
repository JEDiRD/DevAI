"""End-to-end regression for canonical package-member path derivation.

Proven defect: ``install-support.ps1`` derived a member's manifest-relative path
by subtracting ``$PackageRoot.Length`` from the enumerated ``FullName``. That
assumes the caller-supplied root and the enumerated path share one lexical
spelling. On canonical windows-2025 runners ``TEMP`` is the 8.3 alias
``C:\\Users\\RUNNER~1\\...``, so a byte-for-byte VALID package was rejected as
``UNMANIFESTED_PACKAGE_FILE``.

These tests drive the REAL installer (``-ValidateOnly``) over the SAME package
bytes addressed through a long root spelling and through a dynamically
discovered 8.3 SHORT root spelling, and require both to validate with the same
logical member set. The short alias is never hardcoded; when a host has 8.3
name generation disabled the short-path test reports an environment limitation
instead of a false pass.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy" / "windows"
INSTALLER = DEPLOY / "install-worker.ps1"
SUPPORT = DEPLOY / "install-support.ps1"

IS_WINDOWS = os.name == "nt"
POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build_helpers():
    """Reuse the canonical package builder so bytes match the rest of the suite."""
    return _load("t_core_for_paths", REPO / "tests" / "test_release_installer_core.py")


def run_validate(package_root: Path) -> tuple[int, str]:
    """Invoke the real installer in -ValidateOnly against package_root."""
    script = ("$ErrorActionPreference='Stop'\n"
              "& $args[0] -PackageRoot $args[1] -ValidateOnly\n")
    tmp = Path(tempfile.mkdtemp())
    try:
        probe = tmp / "probe.ps1"
        probe.write_text(script, encoding="utf-8")
        env = {**os.environ,
               "PSModulePath": str(Path(os.environ["SystemRoot"]) / "System32"
                                   / "WindowsPowerShell" / "v1.0" / "Modules")}
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-File", str(probe), str(INSTALLER), str(package_root)],
            capture_output=True, text=True, timeout=300, env=env)
        return result.returncode, result.stdout + result.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def member_set(package_root: Path) -> list[str]:
    out = []
    for p in sorted(package_root.rglob("*")):
        if p.is_file():
            out.append(p.relative_to(package_root).as_posix())
    return sorted(out)


def short_alias(path: Path) -> str | None:
    """Discover the real 8.3 short form of an existing directory.

    The path is embedded in the command body because Windows PowerShell does not
    bind trailing arguments to $args[] after -Command.
    """
    literal = str(path).replace("'", "''")
    cmd = ("$fso = New-Object -ComObject Scripting.FileSystemObject; "
           "$s = $fso.GetFolder('" + literal + "').ShortPath; "
           "if ($s) { Write-Output $s }")
    r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, text=True)
    candidate = r.stdout.strip().splitlines()[-1].strip() if r.stdout.strip() else ""
    if not candidate:
        return None
    if candidate.lower() == str(path).lower():
        return None
    return candidate if Path(candidate).exists() else None


@unittest.skipUnless(IS_WINDOWS and POWERSHELL, "Windows PowerShell required")
class PackagePathCanonicalizationTests(unittest.TestCase):
    """The same package bytes must validate through both root spellings."""

    maxDiff = None

    def _validate_both(self):
        helpers = _build_helpers()
        long_parent = Path(tempfile.mkdtemp())
        short_parent = None
        try:
            package = long_parent / "pkg"
            package.mkdir()
            helpers.make_package(package)
            helpers.seed_aggregate(package)

            rc_long, text_long = run_validate(package)
            self.assertEqual(0, rc_long,
                             "long spelling must validate: " + text_long[-500:])
            self.assertIn("DEVAI_PACKAGE_VALIDATED", text_long)
            long_members = member_set(package)
            long_digest = {p.name: p.stat().st_size for p in package.rglob("*") if p.is_file()}

            alias = short_alias(long_parent)
            if alias is None:
                self.skipTest("ENVIRONMENT_LIMITATION: 8.3 name generation unavailable "
                              "on this host; canonical windows-2025 CI must execute "
                              "this short-path case")

            short_parent = Path(alias) / package.name
            short_root = Path(alias)
            # the SAME package, addressed only through the short spelling
            self.assertTrue(short_root.exists())
            rc_short, text_short = run_validate(short_package_path(alias, package))
            self.assertEqual(0, rc_short,
                             "short spelling must validate: " + text_short[-500:])
            self.assertIn("DEVAI_PACKAGE_VALIDATED", text_short)

            short_members = member_set(short_package_path(alias, package))
            self.assertEqual(long_members, short_members,
                             "both spellings must yield the same logical member set")

            # and the bytes really are identical
            same = all(
                (short_package_path(alias, package) / n).read_bytes()
                == (package / n).read_bytes()
                for n in long_members)
            self.assertTrue(same, "package bytes must be identical across spellings")
            self.assertEqual(
                long_digest,
                {p.name: p.stat().st_size
                 for p in short_package_path(alias, package).rglob("*") if p.is_file()})
            return long_members
        finally:
            shutil.rmtree(long_parent, ignore_errors=True)
            if short_parent is not None:
                shutil.rmtree(short_parent.parent, ignore_errors=True)

    def test_long_path_validates(self):
        members = self._validate_both()
        self.assertIn("manifest.json", members)

    def test_relative_member_set_matches_across_spellings(self):
        self._validate_both()


def short_package_path(alias: str, package: Path) -> Path:
    """Build the same package location addressed through the short alias."""
    return Path(alias) / package.name


class CanonicalizationShapeTests(unittest.TestCase):
    """Guards the fix itself: one authoritative derivation, no lexical offsets."""

    def test_support_layer_defines_single_authoritative_helper(self):
        text = SUPPORT.read_text(encoding="utf-8")
        self.assertIn("function Get-CanonicalPackageRelativePath", text)
        self.assertIn("function Get-CanonicalLongPath", text)

    def test_no_root_length_subtraction_outside_the_helper(self):
        """No caller may re-derive a member path by subtracting a root length."""
        helper_start = SUPPORT.read_text(encoding="utf-8").index(
            "function Get-CanonicalPackageRelativePath")
        helper_end = SUPPORT.read_text(encoding="utf-8").index(
            "function Assert-ManifestPathSafe")
        helper_body = SUPPORT.read_text(encoding="utf-8")[helper_start:helper_end]
        pattern = re.compile(r"Substring\(\s*\$[A-Za-z_]*(?:Root|root|install)", re.I)
        offenders = []
        for script in sorted(DEPLOY.glob("*.ps1")):
            body = script.read_text(encoding="utf-8")
            for lineno, line in enumerate(body.splitlines(), 1):
                if pattern.search(line):
                    if script == SUPPORT and helper_start >= 0:
                        offset = body.index(line)
                        if helper_start <= offset < helper_end:
                            continue  # the single sanctioned derivation point
                    offenders.append(f"{script.name}:{lineno}: {line.strip()}")
        self.assertEqual([], offenders,
                         "package member paths must use the canonical helper only")

    def test_getrelativepath_is_not_used(self):
        """[IO.Path]::GetRelativePath does not exist on .NET Framework 4.x."""
        offenders = []
        for script in sorted(DEPLOY.glob("*.ps1")):
            for lineno, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(("#", "//")):
                    continue  # prose may name the API to explain why it is avoided
                if "GetRelativePath" in stripped:
                    offenders.append(f"{script.name}:{lineno}: {stripped}")
        self.assertEqual([], offenders,
                         "deployment code must not call an API absent from the "
                         "supported Windows PowerShell 5.1 / .NET Framework runtime")

    def test_both_enumeration_sites_use_the_helper(self):
        support = SUPPORT.read_text(encoding="utf-8")
        worker = (DEPLOY / "install-worker.ps1").read_text(encoding="utf-8")
        self.assertIn("Get-CanonicalPackageRelativePath -PackageRoot $PackageRoot",
                      support)
        self.assertIn("Get-CanonicalPackageRelativePath -PackageRoot $installRoot",
                      worker)

    def test_helper_fails_closed_on_unresolvable_paths(self):
        self.assertIn("PACKAGE_PATH_CANONICALIZATION_FAILED",
                      SUPPORT.read_text(encoding="utf-8"))
        self.assertIn("PACKAGE_MEMBER_OUTSIDE_ROOT",
                      SUPPORT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()