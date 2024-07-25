**Making a new Release of Rosenpass — Cooking Recipe**

If you have to change a file, do what it takes to get the change as commit on the main branch, then **start from step 0**.
If any other issue occurs

0. Make sure you are in the root directory of the project
   - `cd "$(git rev-parse --show-toplevel)"`
1. Make sure you locally checked out the head of the main branch
   - `git stash --include-untracked && git checkout main && git pull`
2. Make sure all tests pass
   - `cargo test`
3. Make sure the current version in `rosenpass/Cargo.toml` matches that in the [last release on GitHub](https://github.com/rosenpass/rosenpass/releases)
   - Only normal releases count, release candidates and draft releases can be ignored
4. Pick the kind of release that you want to make (`major`, `minor`, `patch`, `rc`, ...)
   - See `cargo release --help` for more information on the available release types
   - Pick `rc` if in doubt
5. Try to release a new version
   - `cargo release rc --package rosenpass`
   - An issue was reported? Go fix it, start again with step 0!
6. Actually make the release
   - `cargo release rc --package rosenpass --execute`
   - Tentatively wait for any interactions, such as entering ssh keys etc.
   - You may be asked for your ssh key multiple times!

**Frequently Asked Questions (FAQ)**

- You have untracked files, which `cargo release` complains about?
  - `git stash --include-untracked`
- You cannot push to crates.io because you are not logged in?
  - Follow the steps displayed in [`cargo login`](https://doc.rust-lang.org/cargo/commands/cargo-login.html)
- How is the release page added to [GitHub Releases](https://github.com/rosenpass/rosenpass/releases) itself?
  - Our CI Pipeline will create the release, once `cargo release` pushed the new version tag to the repo. The new release should pop up almost immediately in [GitHub Releases](https://github.com/rosenpass/rosenpass/releases) after the [Actions/Release](https://github.com/rosenpass/rosenpass/actions/workflows/release.yaml) pipeline started.
- No new release pops up in the `Release` sidebar element on the [main page](https://github.com/rosenpass/rosenpass)
  - Did you push a `rc` release? This view only shows non-draft release, but `rc` releases are considered as draft. See [Releases](https://github.com/rosenpass/rosenpass/releases) page to see all (including draft!) releases.
- The release page was created on GitHub, but there are no assets/artifacts other than the source code tar ball/zip?
  - The artifacts are generated and pushed automatically to the release, but this takes some time (a couple of minutes). You can check the respective CI pipeline: [Actions/Release](https://github.com/rosenpass/rosenpass/actions/workflows/release.yaml), which should start immediately after `cargo release` pushed the new release tag to the repo. The release artifacts only are added later to the release, once all jobs in bespoke pipeline finished.
- How are the release artifacts generated, and what are they?
  - The release artifacts are built using one Nix derivation per platform, `nix build .#release-package`. It contains both statically linked versions of `rosenpass` itself and OCI container images.
