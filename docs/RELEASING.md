# Release integrity and repair

The updater and installer consume raw `rout-linux-amd64` or `rout-linux-arm64` binaries and `checksums.txt`. These are the two supported targets; source archives cannot replace them. `version.txt` records the tag. The manifest covers both binaries and `version.txt` exactly once.

The tag CI workflow runs tests, race tests, static/security checks and platform regressions before cross-compilation. Publication validates the artifact checksums, ELF architectures, Linux/CGO settings and embedded clean source commit. Only the publishing job receives release-write permissions; provenance attestation retains its separate required OIDC/attestation permissions. Ordinary pushes to main never publish.

New releases start as drafts. All four files must upload and pass API, size/digest and downloaded-byte checks before publication. Public updater URLs are downloaded without authentication and checked again after publication. A failed or incomplete publication fails the workflow. An existing release is checked and completed instead of skipped. Existing assets must match the verified build; conflicting files fail without deletion or overwrite. Unrelated assets and release metadata remain intact. Publication/repair for the same tag is serialized.

## Repair an existing release

Use **Actions → Repair existing release → Run workflow**, on `main`. Supply the existing tag and its exact original 40-character commit. The build job verifies the tag, checks the source version, runs Go tests/race/vet and builds only that source. The upload job uses the reviewed automation from the workflow commit, validates embedded provenance and rechecks the remote tag. It requires the release to exist and never creates or moves tags, creates a release, deletes assets or clobbers files. Existing drafts remain drafts during repair.

For the v0.3.6 repair:

```sh
gh workflow run repair-release.yml --repo VAR7IANT/Rout --ref main \
  -f tag=v0.3.6 -f commit=da82e29b5a6a1749958db63ae1a4c8ff558196c2
gh run list --repo VAR7IANT/Rout --workflow repair-release.yml
```

Do not rerun the old tag workflow expecting newer automation: it retains its historical source. Never relabel a main build as an old release. If a repaired asset conflicts with an existing file, inspect it and recover the original verified artifact; the repair must fail rather than silently replace it.

If Actions is unavailable, build the unchanged tag in an isolated checkout with a supported Go toolchain:

```sh
git fetch origin tag v0.3.6
test "$(git rev-parse 'v0.3.6^{commit}')" = da82e29b5a6a1749958db63ae1a4c8ff558196c2
git worktree add --detach ../rout-v036-repair v0.3.6
(cd ../rout-v036-repair && sh scripts/release.sh && dist/rout-linux-amd64 version)
python3 scripts/release_assets.py v0.3.6 da82e29b5a6a1749958db63ae1a4c8ff558196c2 \
  ../rout-v036-repair/dist --repo VAR7IANT/Rout --existing-only
```

The publisher needs Python 3.9+, Go (for reading build metadata), curl and an authenticated `gh` with release-write access. These are CI/operator tools, not Rout runtime dependencies. No VPS operation or runtime configuration change is needed to repair GitHub assets. SHA256 establishes integrity; independent authenticity checks use the GitHub build-provenance attestation and a recent `gh attestation verify`.

## Version commands

The `main` fix adds `rout --version` and `rout -v` alongside `rout version`, without loading configuration or requiring root. This is unreleased application code. The repaired v0.3.6 binaries retain the original tagged application, including its old CLI behavior; use `rout version` there. Do not rebuild v0.3.6 with this fix inserted.
