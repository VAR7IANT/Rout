#!/usr/bin/env python3
"""Validate, complete and verify Rout releases; Python stdlib and gh only."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile


FILES = ("rout-linux-amd64", "rout-linux-arm64", "version.txt", "checksums.txt")


class ReleaseError(Exception):
    pass


def command(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        detail = re.sub(r"https?://\S+", "[URL withheld]", result.stderr.strip())
        raise ReleaseError(f"{args[0]} {args[1]} failed: {detail[:1000]}")
    return result.stdout


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validate(directory, tag, commit, run=command):
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ReleaseError("Expected a stable vMAJOR.MINOR.PATCH tag")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("Expected the exact 40-character source commit")
    directory = pathlib.Path(directory)
    for name in FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ReleaseError(f"Missing, empty or unsafe release file: {name}")
    if (directory / "version.txt").read_bytes() != (tag + "\n").encode():
        raise ReleaseError("version.txt does not match the requested tag")
    entries = {}
    for line in (directory / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (rout-linux-amd64|rout-linux-arm64|version\.txt)", line)
        if not match or match[2] in entries:
            raise ReleaseError("Malformed, duplicate or unexpected checksum entry")
        entries[match[2]] = match[1]
    if set(entries) != set(FILES[:-1]):
        raise ReleaseError("Checksums must cover both binaries and version.txt exactly once")
    for name, expected in entries.items():
        if digest(directory / name) != expected:
            raise ReleaseError(f"SHA256 mismatch: {name}")
    for name, machine in ((FILES[0], 62), (FILES[1], 183)):
        with (directory / name).open("rb") as stream:
            header = stream.read(20)
        if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != machine:
            raise ReleaseError(f"Wrong Linux ELF architecture: {name}")
        info = run(["go", "version", "-m", str(directory / name)])
        for field in ("GOOS=linux", "CGO_ENABLED=0", "GOARCH=" + name.removeprefix("rout-linux-"), "vcs.revision=" + commit, "vcs.modified=false"):
            if not re.search(r"^\s*build\s+" + re.escape(field) + r"$", info, re.MULTILINE):
                raise ReleaseError(f"Missing build provenance ({field}): {name}")
    return {name: digest(directory / name) for name in FILES}


def release(repo, tag, run):
    # Only a real HTTP 404 means absent; authentication/network errors must fail.
    # The releases/tags endpoint excludes drafts. List releases to locate
    # an existing draft before falling back to the published tag endpoint.
    page = 1
    while True:
        items = json.loads(run(["gh", "api", f"repos/{repo}/releases?per_page=100&page={page}"]))
        if not isinstance(items, list):
            raise ReleaseError("Invalid releases list API response")
        for item in items:
            if item.get("tag_name") == tag:
                info = item
                break
        else:
            if len(items) < 100:
                return None
            page += 1
            continue
        break
    if info.get("tag_name") != tag or not isinstance(info.get("id"), int) or not isinstance(info.get("assets"), list):
        raise ReleaseError("Invalid release API response")
    if info.get("prerelease"):
        raise ReleaseError("Stable tag unexpectedly refers to a prerelease")
    return info


def verify_tag(repo, tag, commit, run):
    obj = json.loads(run(["gh", "api", f"repos/{repo}/git/ref/tags/{tag}"])).get("object", {})
    for _ in range(8):
        if obj.get("type") == "commit" and obj.get("sha") == commit:
            return
        if obj.get("type") != "tag" or not re.fullmatch(r"[0-9a-f]{40}", obj.get("sha", "")):
            break
        obj = json.loads(run(["gh", "api", f"repos/{repo}/git/tags/{obj['sha']}"])).get("object", {})
    raise ReleaseError("Remote tag no longer matches the original source commit")


def verify_remote(repo, tag, info, hashes, directory, run, complete=True):
    present = {}
    for asset in info["assets"]:
        name = asset.get("name")
        if name not in FILES:
            continue  # Preserve unrelated assets; never delete or clobber.
        if name in present or asset.get("state") != "uploaded" or asset.get("size") != (directory / name).stat().st_size:
            raise ReleaseError(f"Duplicate, incomplete or conflicting release asset: {name}")
        if asset.get("digest") not in (None, "sha256:" + hashes[name]):
            raise ReleaseError(f"Conflicting API asset digest: {name}")
        present[name] = asset
    if complete and set(present) != set(FILES):
        raise ReleaseError("Release API is missing required updater assets")
    with tempfile.TemporaryDirectory(prefix="rout-release-check-") as temporary:
        for name in present:
            run(["gh", "release", "download", tag, "--repo", repo, "--pattern", name, "--dir", temporary])
            downloaded = pathlib.Path(temporary) / name
            if not downloaded.is_file() or digest(downloaded) != hashes[name]:
                raise ReleaseError(f"Downloaded asset SHA256 mismatch: {name}")
    return set(present)


def publish(directory, tag, commit, repo, existing_only=False, notes=None, run=command):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ReleaseError("Invalid repository")
    directory = pathlib.Path(directory).resolve()
    hashes = validate(directory, tag, commit, run)
    verify_tag(repo, tag, commit, run)
    info = release(repo, tag, run)
    if info is None:
        if existing_only:
            raise ReleaseError("Repair requires an existing release; nothing created")
        if not notes or not pathlib.Path(notes).is_file():
            raise ReleaseError("Release notes file required to create a draft")
        run(["gh", "release", "create", tag, "--repo", repo, "--verify-tag", "--draft", "--title", "Rout " + tag, "--notes-file", str(notes)])
        info = release(repo, tag, run)
        if info is None or not info.get("draft"):
            raise ReleaseError("Draft release creation could not be verified")
    release_id = info["id"]
    present = verify_remote(repo, tag, info, hashes, directory, run, complete=False)
    for name in FILES:
        if name not in present:
            run(["gh", "release", "upload", tag, "--repo", repo, str(directory / name)])
    info = release(repo, tag, run)
    if info is None or info["id"] != release_id:
        raise ReleaseError("Release identity changed during publication")
    verify_remote(repo, tag, info, hashes, directory, run)
    verify_tag(repo, tag, commit, run)
    if info.get("draft") and not existing_only:
        # Publish only after all assets are verified; retain drafts on failure.
        run(["gh", "release", "edit", tag, "--repo", repo, "--draft=false"])
        info = release(repo, tag, run)
        if info is None or info["id"] != release_id or info.get("draft"):
            raise ReleaseError("Published release state could not be verified")
        verify_remote(repo, tag, info, hashes, directory, run)
    if not info.get("draft"):
        # Unauthenticated public downloads independently prove the updater URLs work.
        with tempfile.TemporaryDirectory(prefix="rout-public-check-") as temporary:
            for name in FILES:
                target = pathlib.Path(temporary) / name
                run(["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--retry", "2", "--connect-timeout", "15", "--max-time", "180", f"https://github.com/{repo}/releases/download/{tag}/{name}", "-o", str(target)])
                if not target.is_file() or digest(target) != hashes[name]:
                    raise ReleaseError(f"Public download SHA256 mismatch: {name}")
    verify_tag(repo, tag, commit, run)
    print(f"Verified {tag}: release {release_id}, all {len(FILES)} required assets and SHA256 digests")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("commit")
    parser.add_argument("directory")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--existing-only", action="store_true")
    parser.add_argument("--notes")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.validate_only:
            validate(args.directory, args.tag, args.commit)
        else:
            publish(args.directory, args.tag, args.commit, args.repo, args.existing_only, args.notes)
    except (ReleaseError, ValueError, OSError) as error:
        parser.exit(1, f"Release verification failed: {error}\n")


if __name__ == "__main__":
    main()
