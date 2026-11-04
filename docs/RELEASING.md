# Release integrity and repair

The updater and installer consume raw `rout-linux-amd64` or `rout-linux-arm64` binaries and `checksums.txt`. These are the two supported targets; source archives cannot replace them. `version.txt` records the tag. The manifest covers both binaries and `version.txt` exactly once.

The tag CI workflow runs tests, race tests, static/security checks and platform regressions before cross-compilation. Publication validates the artifact checksums, ELF architectures, Linux/CGO settings and embedded clean source commit. Only the publishing job receives release-write permissions; provenance attestation retains its separate required OIDC/attestation permissions. Ordinary pushes to main never publish.

New releases start as drafts. All four files must upload and pass API, size/digest and downloaded-byte checks before publication. Public updater URLs are downloaded without authentication and checked again after publication. A failed or incomplete publication fails the workflow. An existing release is checked and completed instead of skipped. Existing assets must match the verified build; conflicting files fail without deletion or overwrite. Unrelated assets and release metadata remain intact. Publication/repair for the same tag is serialized.

## Release order: publish first, merge second

`main/install.sh` is what the README tells people to run, and it pins one version (`VERSION=${ROUT_VERSION:-vX.Y.Z}`; CI requires it to equal the compiled version). If the commit that bumps the pin reaches `main` before the release exists, every new install answers **HTTP 404** until the release is published. The installer fails closed — nothing is replaced, it names the missing release and never installs another version — but the window is still a broken installer. `rout update` is not affected: it reads GitHub's *latest published* release. Releases up to v0.5.0 were tagged on the merge commit, i.e. after that window; from v0.5.1 on the order is:

1. The release PR is open and **every required check is green on the exact head commit**, including the real-host acceptance listed in the PR. Until the release is published, the *Release order guard* check shows a warning (`Release not published yet`): that is the reminder not to merge.
2. With the maintainer's explicit approval, tag **that head commit** (not a later one) and push the tag:

   ```sh
   git fetch origin
   git tag -a vX.Y.Z -m 'Rout vX.Y.Z' <verified-head-sha>
   git push origin vX.Y.Z
   ```

   The tag workflow re-runs every check, builds both binaries, creates a draft release, uploads and verifies all four assets, publishes, and re-downloads them publicly. A published tag is never moved: if something has to change after tagging, the fix ships as the next patch version.
3. Confirm the release is public and the installer works against it: `ROUT_INSTALL_DIR=$(mktemp -d) ROUT_VERSION=vX.Y.Z sh install.sh` (it verifies SHA256 and the reported version before installing anything), then `rout update` on a host that has the previous version.
4. **Only now merge the PR.** Use a *merge commit*, so that the tagged commit is an ancestor of `main`; a squash or rebase merge leaves the tag on a commit that is not in `main`'s history (the release is still valid, but `git describe` and provenance lookups become confusing). `main` then points at a release that already exists.
5. The *Release order guard* fails any push to `main` whose installer points at an unpublished release, so a wrong order is noticed immediately instead of by the first user.

What the installer guarantees (`scripts/test-install.sh` tests the unmodified `install.sh` in CI, with a fake `curl` that serves local artifacts and refuses every URL except `https://github.com/VAR7IANT/Rout/releases/download/…`): both `rout-linux-amd64` and `rout-linux-arm64` are requested by exactly the names `release.sh` produces; the SHA256 comes from the same release's `checksums.txt` and must be unique and match; the binary must report the requested version; the old executable is replaced only by an atomic rename inside the destination directory, after all checks; a missing release (404), a tampered file, a missing or duplicate checksum and a wrong version leave the existing installation untouched; `ROUT_VERSION` installs exactly that release. CI also installs the latest *published* release with the current `install.sh`. This does not replace a real tag run, which is the only proof that GitHub serves the files.

## Repair an existing release

Use **Actions → Repair existing release → Run workflow**, on `main`. Supply the existing tag and its exact original 40-character commit. The build job verifies the tag, checks the source version, runs Go tests/race/vet and builds only that source. The upload job uses the reviewed automation from the workflow commit, validates embedded provenance and rechecks the remote tag. Signed provenance explicitly records the original tag/source commit as a resolved dependency, separate from the newer repair workflow's commit; both binary signatures are verified before upload. Only that job receives the required release/OIDC/attestation permissions. It requires the release to exist and never creates or moves tags, creates a release, deletes assets or clobbers files. Existing drafts remain drafts during repair.

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
