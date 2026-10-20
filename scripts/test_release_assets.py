import copy
import hashlib
import json
import pathlib
import tempfile
import unittest

from release_assets import FILES, ReleaseError, publish, validate


TAG = "v0.3.6"
COMMIT = "d" * 40


class GitHub:
    def __init__(self, directory, exists=True, draft=False):
        self.directory = directory
        self.info = {"id": 123, "tag_name": TAG, "assets": [], "draft": draft, "prerelease": False} if exists else None
        self.data = {}
        self.calls = []
        self.fail_upload = None
        self.fail_api = False
        self.omit_final_asset = False
        self.fail_public = False
        self.tag_commit = COMMIT

    def add(self, name, data=None):
        if data is None:
            data = (self.directory / name).read_bytes()
        self.data[name] = data
        self.info["assets"].append({"name": name, "size": len(data), "state": "uploaded", "digest": "sha256:" + hashlib.sha256(data).hexdigest()})

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ["go", "version", "-m"]:
            arch = pathlib.Path(args[3]).name.removeprefix("rout-linux-")
            return "\n".join("\tbuild\t" + value for value in ["GOOS=linux", "CGO_ENABLED=0", "GOARCH=" + arch, "vcs.revision=" + COMMIT, "vcs.modified=false"])
        if args[:2] == ["gh", "api"]:
            if "/git/ref/tags/" in args[2]:
                return json.dumps({"object": {"type": "commit", "sha": self.tag_commit}})
            if self.fail_api:
                raise ReleaseError("HTTP 401")
            if self.info is None:
                raise ReleaseError("HTTP 404")
            info = copy.deepcopy(self.info)
            if self.omit_final_asset and len(self.data) == 4:
                info["assets"].pop()
            return json.dumps(info)
        if args[:3] == ["gh", "release", "create"]:
            self.info = {"id": 123, "tag_name": TAG, "assets": [], "draft": True, "prerelease": False}
        elif args[:3] == ["gh", "release", "upload"]:
            name = pathlib.Path(args[-1]).name
            if self.fail_upload == name:
                raise ReleaseError("upload interrupted")
            self.add(name)
        elif args[:3] == ["gh", "release", "download"]:
            name = args[args.index("--pattern") + 1]
            path = pathlib.Path(args[args.index("--dir") + 1]) / name
            path.write_bytes(self.data[name])
        elif args[:3] == ["gh", "release", "edit"]:
            self.info["draft"] = False
        elif args[0] == "curl":
            name = args[-3].rsplit("/", 1)[1]
            pathlib.Path(args[-1]).write_bytes(b"bad response" if self.fail_public else self.data[name])
        else:
            raise AssertionError(args)
        return ""


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        for name, machine in ((FILES[0], 62), (FILES[1], 183)):
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = machine.to_bytes(2, "little")
            (self.directory / name).write_bytes(header + b"test build")
        (self.directory / "version.txt").write_text(TAG + "\n")
        self.checksums()
        self.gh = GitHub(self.directory)
        self.notes = self.directory / "notes.md"
        self.notes.write_text("Release notes")

    def checksums(self):
        (self.directory / "checksums.txt").write_text("".join(hashlib.sha256((self.directory / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in FILES[:-1]))

    def publish(self, existing_only=True):
        publish(self.directory, TAG, COMMIT, "VAR7IANT/Rout", existing_only, self.notes, self.gh)

    def test_empty_existing_release_is_completed_and_verified(self):
        self.publish()
        self.assertEqual(set(self.gh.data), set(FILES))
        self.assertEqual(self.gh.info["id"], 123)
        self.assertFalse(any(call[2:3] == ["create"] for call in self.gh.calls))
        self.assertEqual(sum(call[0] == "curl" for call in self.gh.calls), 4)
        self.assertEqual(sum(call[1:3] == ["release", "download"] for call in self.gh.calls), 4)

    def test_partial_release_and_repeat_are_idempotent(self):
        self.gh.add(FILES[0])
        self.gh.add("unrelated.txt", b"preserve")
        self.publish()
        self.publish()
        self.assertEqual(sum(call[1:3] == ["release", "upload"] for call in self.gh.calls), 3)
        self.assertEqual(self.gh.data["unrelated.txt"], b"preserve")
        self.assertFalse(any("--clobber" in call for call in self.gh.calls))

    def test_conflicting_existing_asset_is_never_overwritten(self):
        self.gh.add(FILES[0], b"different")
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertFalse(any(call[1:3] == ["release", "upload"] for call in self.gh.calls))

    def test_absent_release_and_auth_errors_never_create_during_repair(self):
        for absent in [True, False]:
            with self.subTest(absent=absent):
                self.gh = GitHub(self.directory, exists=not absent)
                self.gh.fail_api = not absent
                with self.assertRaises(ReleaseError):
                    self.publish()
                self.assertFalse(any(call[2:3] == ["create"] for call in self.gh.calls))

    def test_new_release_stays_draft_on_upload_failure(self):
        self.gh = GitHub(self.directory, exists=False)
        self.gh.fail_upload = FILES[1]
        with self.assertRaises(ReleaseError):
            self.publish(existing_only=False)
        self.assertTrue(self.gh.info["draft"])
        self.assertFalse(any(call[2:3] == ["edit"] for call in self.gh.calls))

    def test_new_release_is_published_only_after_verification(self):
        self.gh = GitHub(self.directory, exists=False)
        self.publish(existing_only=False)
        edit = next(i for i, call in enumerate(self.gh.calls) if call[2:3] == ["edit"])
        self.assertEqual(sum(call[1:3] == ["release", "download"] for call in self.gh.calls[:edit]), 4)
        self.assertFalse(self.gh.info["draft"])

    def test_incomplete_api_or_bad_public_response_fails(self):
        for failure in ["omit_final_asset", "fail_public"]:
            with self.subTest(failure=failure):
                self.gh = GitHub(self.directory)
                setattr(self.gh, failure, True)
                with self.assertRaises(ReleaseError):
                    self.publish()

    def test_duplicate_api_assets_and_download_corruption_fail(self):
        self.gh.add(FILES[0])
        self.gh.info["assets"].append(copy.deepcopy(self.gh.info["assets"][0]))
        with self.assertRaises(ReleaseError):
            self.publish()
        self.gh.info["assets"].pop()
        self.gh.data[FILES[0]] = b"corrupted in transit"
        with self.assertRaises(ReleaseError):
            self.publish()

    def test_tag_mismatch_aborts_before_upload(self):
        self.gh.tag_commit = "e" * 40
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertFalse(any(call[1:3] == ["release", "upload"] for call in self.gh.calls))

    def test_missing_corrupt_architecture_manifest_or_commit_fails_before_api(self):
        good = {name: (self.directory / name).read_bytes() for name in FILES}
        for failure in ["missing", "hash", "arch", "manifest", "version", "commit", "symlink"]:
            with self.subTest(failure=failure):
                for name, data in good.items():
                    path = self.directory / name
                    if path.is_symlink():
                        path.unlink()
                    path.write_bytes(data)
                expected_commit = COMMIT
                if failure == "missing":
                    (self.directory / FILES[1]).unlink()
                elif failure == "hash":
                    (self.directory / FILES[0]).write_bytes(b"corrupt")
                elif failure == "arch":
                    (self.directory / FILES[1]).write_bytes(good[FILES[0]])
                    self.checksums()
                elif failure == "manifest":
                    (self.directory / "checksums.txt").write_text("0" * 64 + "  ../../unexpected\n")
                elif failure == "version":
                    (self.directory / "version.txt").write_text("v9.9.9\n")
                    self.checksums()
                elif failure == "commit":
                    expected_commit = "e" * 40
                else:
                    (self.directory / FILES[1]).unlink()
                    (self.directory / FILES[1]).symlink_to(self.directory / FILES[0])
                self.gh.calls.clear()
                with self.assertRaises(ReleaseError):
                    validate(self.directory, TAG, expected_commit, self.gh)
                self.assertFalse(any(call[0] == "gh" for call in self.gh.calls))


if __name__ == "__main__":
    unittest.main()
