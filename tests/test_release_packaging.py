"""RH-B 5A-1: immutable packaging boundary.

These tests pin the BUILD side only. The install/provision side (target-side
personal fixture, target-side credential) is covered in 5A-2.

The central property is that build-package.py is a pure, secret-free,
machine-independent step: given identical inputs it emits identical bytes, and
no target or operator state can influence it.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
BUILDER = REPO / "deploy" / "windows" / "build-package.py"
SECURITY_HEAD = "0bd8ebfb0326935a1e7d910a971be18cb384ec42"

# Stage-B historical aggregates, over the four-root production boundary.
V1_PRODUCTION = "1a36525ec655967e7ae9fbda9c968e49eace64983c906e7c99c7fcb28542e03b"
V1_MIGRATIONS = "d1d0ed906ff0b614d9f04c05f327aa4d1416fccf67838ba70ee125f2ead6c920"
V1_ROOTS = ("controller/devai", "worker_agent", "migrations", "deploy")


def load_builder():
    spec = importlib.util.spec_from_file_location("rb_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def executable_source(path=BUILDER):
    """AST-normalised source: docstrings and comments stripped.

    Prose must neither satisfy nor break an invariant, so every source-level
    assertion is evaluated against executable code only.
    """
    import ast

    class Strip(ast.NodeTransformer):
        def _strip(self, node):
            self.generic_visit(node)
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
            return node

        visit_FunctionDef = _strip
        visit_AsyncFunctionDef = _strip
        visit_ClassDef = _strip
        visit_Module = _strip

    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return ast.unparse(Strip().visit(tree))


def git(*args, binary=False):
    out = subprocess.run(["git", "-C", str(REPO)] + list(args),
                         capture_output=True, check=True).stdout
    return out if binary else out.decode("utf-8")


def v1_aggregate(paths):
    lines = []
    for path in sorted(paths, key=lambda p: p.encode("utf-8")):
        blob = git("show", "%s:%s" % (SECURITY_HEAD, path), binary=True)
        lines.append("%s  %d  %s" % (hashlib.sha256(blob).hexdigest(),
                                      len(blob), path))
    return hashlib.sha256(("\r\n".join(lines) + "\r\n").encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# Legacy build inputs must fail closed.
# ----------------------------------------------------------------------
class LegacyBuildArgumentTests(unittest.TestCase):
    """--existing-config / --reuse-personal-fixture are no longer build inputs."""

    def setUp(self):
        self.builder = load_builder()

    def _expect_fail_closed(self, extra_arg):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "package"
            with self.assertRaises(self.builder.BuildError) as ctx:
                self.builder.main(["--destination", str(destination)] + extra_arg)
            self.assertIn("installation/provisioning", str(ctx.exception))
            self.assertFalse(destination.exists(),
                             "no artifact may be created on the rejection path")

    def test_existing_config_is_rejected(self):
        self._expect_fail_closed(["--existing-config", "C:/some/config.json"])

    def test_reuse_personal_fixture_is_rejected(self):
        self._expect_fail_closed(
            ["--reuse-personal-fixture", "C:/Users/someone/fixture"])

    def test_rejection_message_does_not_echo_supplied_values(self):
        """A supplied path must never leak into the error surface."""
        secretish = "C:/secret-operator-path/token-store.json"
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.main(["--destination", "unused",
                               "--existing-config", secretish])
        message = str(ctx.exception)
        self.assertNotIn(secretish, message)
        self.assertNotIn("secret-operator-path", message)
        self.assertNotIn("token-store", message)

    def test_rejection_happens_before_any_credential_or_profile_access(self):
        """The legacy path must be refused before anything is read."""
        reads = []
        real_open = open

        def spy(file, *a, **k):
            reads.append(str(file))
            return real_open(file, *a, **k)

        with patch("builtins.open", spy):
            with self.assertRaises(self.builder.BuildError):
                self.builder.main(["--destination", "unused",
                                   "--existing-config", "x.json"])
        self.assertEqual([], reads,
                         "no file may be opened while refusing a legacy option")

    def test_legacy_options_are_recognised_not_silently_ignored(self):
        """A legacy option with a value must fail; with no value it is a no-op.

        argparse.SUPPRESS keeps them out of --help, but they are still PARSED,
        so a value is detected and refused rather than ignored.
        """
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "package"
            with self.assertRaises(self.builder.BuildError):
                self.builder.main(["--destination", str(destination),
                                   "--existing-config", "anything.json"])
            self.assertFalse(destination.exists())


# ----------------------------------------------------------------------
# The build must never emit secrets or target state.
# ----------------------------------------------------------------------
class SecretFreeBuildTests(unittest.TestCase):
    def setUp(self):
        self.builder = load_builder()

    def test_source_has_no_dpapi_or_credential_imports(self):
        """The build must not even be able to reach credential material."""
        source = executable_source()
        for forbidden in ("WindowsDpapiCredentialStore", "ServiceCredentialStore",
                          "credential_store", "AgentConfig"):
            self.assertNotIn(forbidden, source,
                             "build must not import %s" % forbidden)

    def test_source_has_no_personal_profile_discovery(self):
        source = executable_source()
        self.assertNotIn("Path.home()", source)
        self.assertNotIn("prepare_personal_fixture", source)
        self.assertNotIn("set_directory_acl", source)

    def test_source_has_no_host_runtime_identity(self):
        """Evaluated on executable code only.

        A docstring mentioning sys.base_prefix must not fail this test, and
        prose must not be able to satisfy it either.
        """
        source = executable_source()
        self.assertNotIn("sys.base_prefix", source,
                         "package identity must not come from host Python")
        self.assertNotIn("sys.executable", source)
        self.assertNotIn("sys.version_info", source)

    def test_worker_dpapi_is_forbidden_payload(self):
        self.assertTrue(self.builder._is_forbidden("worker.dpapi"))
        self.assertTrue(self.builder._is_forbidden("host-runtime/worker.dpapi"))

    def test_fixture_paths_are_forbidden_payload(self):
        for rel in ("personal_denial_fixture",
                    "control/personal-denial.fixture",
                    "service.json"):
            self.assertTrue(self.builder._is_forbidden(rel), rel)

    def test_manifest_refuses_forbidden_payload(self):
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.build_manifest_document(
                None, entries=[("worker.dpapi", b"secret")])
        self.assertIn("FORBIDDEN_PAYLOAD", str(ctx.exception))

    def test_manifest_json_is_real_json_not_line_oriented(self):
        """manifest.json MUST parse as JSON. It is not a V2 text file."""
        import json
        data = self.builder.build_manifest_document(
            None, entries=[("a.txt", b"a"), ("b.txt", b"bb")])
        doc = json.loads(data.decode("utf-8"))
        self.assertEqual("DEVAI_PACKAGE_MANIFEST", doc["manifest_format"])
        self.assertEqual(1, doc["manifest_schema_version"])
        self.assertIsInstance(doc["files"], list)

    def test_v2_identity_serialization_is_separate_and_lf(self):
        """V2 is the canonical identity algorithm, not the storage format."""
        data = self.builder.serialize_manifest_v2(
            [("a.txt", b"a"), ("b.txt", b"bb")])
        self.assertTrue(data.startswith(b"# MANIFEST_FORMAT_V2\n"))
        self.assertNotIn(b"\r\n", data)
        self.assertTrue(data.endswith(b"\n"))

    def test_manifest_and_v2_are_distinct_byte_streams(self):
        v2 = self.builder.serialize_manifest_v2([("a.txt", b"a")])
        doc = self.builder.build_manifest_document(
            None, entries=[("a.txt", b"a")])
        self.assertNotEqual(v2, doc)

    def test_manifest_declares_policy_but_no_concrete_target_state(self):
        import json
        doc = json.loads(self.builder.build_manifest_document(
            None, entries=[("a.txt", b"a")]).decode("utf-8"))
        self.assertIn("requires_worker_identity", doc["policy_requirements"])
        self.assertIn("requires_api_base_url", doc["policy_requirements"])
        self.assertIn("requires_worker_credential", doc["policy_requirements"])
        self.assertIn("requires_personal_profile_denial_fixture",
                      doc["policy_requirements"])
        banned = {"worker_id", "api_base_url", "personal_denial_fixture",
                  "credential_path", "token"}
        def keys(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield k
                    yield from keys(v)
            elif isinstance(node, list):
                for v in node:
                    yield from keys(v)
        self.assertEqual(set(), banned & set(keys(doc)))

    def test_manifest_records_runtime_identity(self):
        import json
        lock = self.builder.load_runtime_lock()
        doc = json.loads(self.builder.build_manifest_document(
            None, entries=[("a.txt", b"a")],
            runtime={"python_version": lock["python_version"],
                     "source_sha256": lock["source_sha256"]},
        ).decode("utf-8"))
        self.assertEqual("3.13.16", doc["runtime"]["python_version"])
        self.assertEqual(lock["source_sha256"], doc["runtime"]["source_sha256"])

    def test_manifest_has_no_bom(self):
        data = self.builder.build_manifest_document(
            None, entries=[("a.txt", b"x")])
        self.assertFalse(data.startswith(b"\xef\xbb\xbf"))


# ----------------------------------------------------------------------
# Determinism and machine-independence.
# ----------------------------------------------------------------------
class BuildDeterminismTests(unittest.TestCase):
    def setUp(self):
        self.builder = load_builder()

    def _package(self, dest):
        self.builder.write_package_files(Path(dest))
        manifest = self.builder.build_manifest_document(dest)
        (Path(dest) / "manifest.json").write_bytes(manifest)
        return hashlib.sha256(manifest).hexdigest()

    def test_two_builds_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = self._package(a)
            second = self._package(b)
            self.assertEqual(first, second)

    def test_userprofile_variation_does_not_change_identity(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            with patch.dict(os.environ, {"USERPROFILE": str(a)}):
                first = self._package(Path(a) / "pkg")
            with patch.dict(os.environ, {"USERPROFILE": str(b)}):
                second = self._package(Path(b) / "pkg")
            self.assertEqual(first, second)

    def test_localappdata_variation_does_not_change_identity(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            with patch.dict(os.environ, {"LOCALAPPDATA": str(a)}):
                first = self._package(Path(a) / "pkg")
            with patch.dict(os.environ, {"LOCALAPPDATA": str(b)}):
                second = self._package(Path(b) / "pkg")
            self.assertEqual(first, second)

    def test_working_directory_does_not_change_identity(self):
        original = os.getcwd()
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            try:
                os.chdir(a)
                first = self._package(Path(a) / "pkg")
                os.chdir(b)
                second = self._package(Path(b) / "pkg")
            finally:
                os.chdir(original)
        self.assertEqual(first, second)

    def test_manifest_enumeration_is_sorted_by_utf8_bytes(self):
        import json
        names = ["b.txt", "A.txt", "a/b.txt", "Z.txt", "ä.txt"]
        doc = self.builder.build_manifest_document(
            None, entries=[(n, b"x") for n in names])
        parsed = json.loads(doc.decode("utf-8"))
        order = [f["path"] for f in parsed["files"]]
        self.assertEqual(
            sorted(order, key=lambda p: p.encode("utf-8")), order)

    def test_package_contains_no_absolute_path_or_username(self):
        """Structural, not keyword matching.

        Source may legitimately mention policy words such as 'AppData' (the
        installer's fixture-placement check), so a bare keyword would fail a
        correct package. What must never appear is a real builder path or the
        operator identity, so those are matched precisely.
        """
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "pkg"
            self._package(dest)
            blob = b"".join(
                p.read_bytes() for p in sorted(dest.rglob("*")) if p.is_file())
            needles = [b"C:\\Users\\", b"/home/", b"/root/", b"\\Users\\",
                       b"USERPROFILE=", b"LOCALAPPDATA="]
            username = os.environ.get("USERNAME")
            if username:
                needles.append(username.encode())
            for needle in needles:
                with self.subTest(needle=needle):
                    self.assertNotIn(needle, blob)

    def test_package_declares_no_absolute_target_path_values(self):
        """No absolute path may appear as a JSON value in the contract."""
        import json
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp) / "pkg"
            self._package(dest)
            document = json.loads(
                (dest / "manifest.json").read_text(encoding="utf-8"))
            for key in ("worker_id", "api_base_url",
                        "personal_denial_fixture", "credential_path"):
                self.assertNotIn(key, document)


# ----------------------------------------------------------------------
# Runtime pin verification.
# ----------------------------------------------------------------------
class RuntimeLockTests(unittest.TestCase):
    def setUp(self):
        self.builder = load_builder()
        self.lock = self.builder.load_runtime_lock()

    def test_runtime_lock_declares_the_canonical_runtime(self):
        self.assertEqual("3.13.16", self.lock["python_version"])
        self.assertEqual("CPython", self.lock["python_implementation"])
        self.assertEqual("97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297",
                         self.lock["source_sha256"])
        self.assertEqual(11439094, self.lock["source_size_bytes"])

    def test_correct_runtime_hash_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "runtime.zip"
            artifact.write_bytes(b"not-the-real-runtime")
            lock = dict(self.lock)
            lock["source_size_bytes"] = artifact.stat().st_size
            lock["source_sha256"] = hashlib.sha256(
                artifact.read_bytes()).hexdigest()
            self.assertEqual(lock["source_sha256"],
                             self.builder.verify_runtime_artifact(artifact, lock))

    def test_runtime_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "runtime.zip"
            artifact.write_bytes(b"tampered-runtime-bytes-here")
            lock = dict(self.lock)
            lock["source_size_bytes"] = artifact.stat().st_size
            lock["source_sha256"] = "0" * 64
            with self.assertRaises(self.builder.BuildError) as ctx:
                self.builder.verify_runtime_artifact(artifact, lock)
            self.assertEqual("RUNTIME_ARTIFACT_SHA256_MISMATCH", str(ctx.exception))

    def test_runtime_size_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "runtime.zip"
            artifact.write_bytes(b"short")
            with self.assertRaises(self.builder.BuildError) as ctx:
                self.builder.verify_runtime_artifact(artifact, self.lock)
            self.assertEqual("RUNTIME_ARTIFACT_SIZE_MISMATCH", str(ctx.exception))

    def test_missing_runtime_artifact_fails_closed(self):
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.verify_runtime_artifact("/nonexistent/runtime.zip",
                                                 self.lock)
        self.assertEqual("RUNTIME_ARTIFACT_MISSING", str(ctx.exception))


# ----------------------------------------------------------------------
# Verifier behaviour.
# ----------------------------------------------------------------------
class ManifestVerifierTests(unittest.TestCase):
    def setUp(self):
        self.builder = load_builder()

    def _make(self, payload):
        temp = tempfile.mkdtemp()
        dest = Path(temp)
        entries = []
        for rel, data in payload.items():
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            entries.append((rel, data))
        manifest = self.builder.build_manifest_document(dest)
        (dest / "manifest.json").write_bytes(manifest)
        self.addCleanup(self._cleanup, temp)
        return dest, manifest

    @staticmethod
    def _cleanup(path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)

    def test_valid_manifest_verifies(self):
        dest, manifest = self._make({"a.txt": b"alpha", "b/c.txt": b"beta"})
        self.assertEqual("DEVAI_PACKAGE_MANIFEST",
                         self.builder.verify_manifest(dest, manifest))

    def test_modified_file_fails(self):
        """Content change of identical length, so HASH catches it not SIZE."""
        dest, manifest = self._make({"a.txt": b"alpha"})
        (dest / "a.txt").write_bytes(b"ALPHA")
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.verify_manifest(dest, manifest)
        self.assertEqual("MANIFEST_HASH_MISMATCH:a.txt", str(ctx.exception))

    def test_wrong_size_fails(self):
        dest, manifest = self._make({"a.txt": b"alpha"})
        (dest / "a.txt").write_bytes(b"alpha-longer")
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.verify_manifest(dest, manifest)
        self.assertEqual("MANIFEST_SIZE_MISMATCH:a.txt", str(ctx.exception))

    def test_unmanifested_file_fails(self):
        dest, manifest = self._make({"a.txt": b"alpha"})
        (dest / "smuggled.txt").write_bytes(b"extra")
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.verify_manifest(dest, manifest)
        self.assertIn("UNMANIFESTED_PAYLOAD", str(ctx.exception))

    def test_missing_manifested_file_fails(self):
        dest, manifest = self._make({"a.txt": b"alpha"})
        (dest / "a.txt").unlink()
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.verify_manifest(dest, manifest)
        self.assertIn("MANIFEST_FILE_MISSING", str(ctx.exception))

    def test_non_json_manifest_fails(self):
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.parse_manifest(b"# MANIFEST_FORMAT_V2\nnot json\n")
        self.assertEqual("MANIFEST_NOT_VALID_JSON", str(ctx.exception))

    def test_unsupported_schema_version_fails(self):
        import json
        payload = json.dumps({"manifest_format": "DEVAI_PACKAGE_MANIFEST",
                              "manifest_schema_version": 99,
                              "files": [{"path": "a", "sha256": "0" * 64,
                                         "size": 1}]}).encode()
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.parse_manifest(payload)
        self.assertEqual("UNSUPPORTED_MANIFEST_SCHEMA_VERSION", str(ctx.exception))

    def test_traversal_and_absolute_paths_are_refused(self):
        import json
        for bad in ("../escape", "/abs", "a/../../b", "C:/x"):
            payload = json.dumps({
                "manifest_format": "DEVAI_PACKAGE_MANIFEST",
                "manifest_schema_version": 1,
                "files": [{"path": bad, "sha256": "0" * 64, "size": 1}]}).encode()
            with self.subTest(path=bad):
                with self.assertRaises(self.builder.BuildError) as ctx:
                    self.builder.parse_manifest(payload)
                self.assertIn("UNSAFE_MANIFEST_PATH", str(ctx.exception))

    def test_case_collision_is_refused(self):
        import json
        payload = json.dumps({
            "manifest_format": "DEVAI_PACKAGE_MANIFEST",
            "manifest_schema_version": 1,
            "files": [{"path": "a.txt", "sha256": "0" * 64, "size": 1},
                      {"path": "A.TXT", "sha256": "1" * 64, "size": 1}]}).encode()
        with self.assertRaises(self.builder.BuildError) as ctx:
            self.builder.parse_manifest(payload)
        self.assertIn("MANIFEST_PATH_COLLISION", str(ctx.exception))

    def test_identity_aggregate_is_recomputed_not_trusted(self):
        from pathlib import Path as _Path
        with tempfile.TemporaryDirectory() as temp:
            dest = _Path(temp)
            (dest / "a.txt").write_bytes(b"alpha")
            doc = self.builder.build_manifest_document(dest)
            (dest / "manifest.json").write_bytes(doc)
            recomputed = self.builder.verify_identity_aggregate(dest, doc)
            self.assertEqual(64, len(recomputed))
            tampered = doc.replace(b'"size": 5', b'"size": 6')
            with self.assertRaises(self.builder.BuildError):
                self.builder.verify_manifest(dest, tampered)


# ----------------------------------------------------------------------
# Historical V1 aggregates must remain reproducible from git objects.
# ----------------------------------------------------------------------
class ManifestV1HistoricalTests(unittest.TestCase):
    """V1 is fully derivable and must keep verifying.

    These read blobs from the security commit, never the worktree, so RH-B's
    intentional deploy/ changes cannot mask a regression.
    """

    def test_v1_production_aggregate_reproduces(self):
        paths = [p for p in git("ls-tree", "-r", "--name-only", SECURITY_HEAD,
                                "--", *V1_ROOTS).splitlines() if p.strip()]
        self.assertEqual(81, len(paths),
                         "production boundary must be exactly 81 files")
        self.assertEqual(V1_PRODUCTION, v1_aggregate(paths))

    def test_v1_migration_aggregate_reproduces(self):
        paths = [p for p in git("ls-tree", "-r", "--name-only", SECURITY_HEAD,
                                "--", "migrations").splitlines() if p.strip()]
        self.assertEqual(15, len(paths))
        self.assertEqual(V1_MIGRATIONS, v1_aggregate(paths))

    def test_v1_serializer_is_crlf_with_trailing_crlf_and_no_header(self):
        builder = load_builder()
        data = builder.manifest_v1_bytes([("a.txt", b"alpha"),
                                          ("b.txt", b"beta")])
        self.assertFalse(data.startswith(b"#"))
        self.assertTrue(data.endswith(b"\r\n"))
        self.assertEqual(2, data.count(b"\r\n"))
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def test_v1_is_never_reinterpreted_as_v2(self):
        """V1 identity text is a separate parser, never the JSON contract."""
        builder = load_builder()
        v1 = builder.manifest_v1_bytes([("a.txt", b"alpha")])
        entries = builder.parse_manifest_v1(v1)
        self.assertEqual("a.txt", entries[0][0])
        with self.assertRaises(builder.BuildError):
            builder.parse_manifest_v1(b"# has a header\r\n")
        with self.assertRaises(builder.BuildError):
            builder.parse_manifest(v1)


if __name__ == "__main__":
    unittest.main()