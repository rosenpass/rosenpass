# Rosenpass Changelog


## v0.2.3 (TODO)
This is a backport release with upgraded dependencies.

### Fixes
- upgrade all dependencies (except `liboqs`)
- upgrade build infrastructure (Nix, CI, formatters)
- add `CHANGELOG.md`


## v0.2.2 (2024-06-05)
This release has no impact for majority of users using Rosenpass with WireGuard.

### Fixes
- fixes vulnerability to prevent output shared key (OSK) to be set or written again on a responder receiving the same InitConf message during a handshake.


## v0.2.1 (2023-11-18)

### Fixes
- improved code quality by applying clippy lints
- removed unnecessary unsafe keyword instances
- addressed stack overflow based test failure using the stacker crate
- fix to reap lingering WireGuard child-processes
- updated manpage
- split code into subcrates, added cargo workspace
- repaired benchmark code
- added a couple more unit tests


## v0.2.0 (2023-09-05)

### Features
- refined artwork
- refined whitepaper
- added examples for keyexchange and CryptoServer usage into code
- added manpage
- rewrote Application server, introduced new CLI, added support for configuration files, added support for multiple listen sockets
- added support for dualstack and non-dualstack IPv4 + IPv6 configurations
- added auto-generated CI Nix workflow and its generator script
- added Mac OS CI build jobs
- added .gitlab-ci.yaml for mirroring to gitlab.com (also add mirror to https://gitlab.com/rosenpass/rosenpass )
- added dualstack support to rp script
- added freebsd support to rp script, prepared for other BSDs

### Fixes
- refined CI for pre-release vs draft vs release artifacts
- added licensing information: MIT and Apache 2.0
- improved consistency of whitepaper by removing synonyms for Key Encapsulation Methods
- renamed protocol::Server to protocol::CryptoServer
- renamed EKEM/SKEM to EphermeralKEM/StaticKEM
- introduced consistent code formatting using cargo-fmt style hints
- further documentation improvements
- fixed crash on empty message handling
- moved from nixpkgs' rustPlatform to naersk + fenix in the nix flake
- reworked CI target platforms (removed i686 Linux); added the i686-linux back in, as the respective OQS bug was resolved
- improved consistency: banned the usage of "private" to describe keys. It is now either "secret" or "public". This avoids the potential for confusion between "pk" (public key) and "pk" (private key) by renaming "private key" to "secret key" (sk).
- added QC CI code independent of Nix (disimalar redundancy, yay!)
- updated crate dependencies
- fixed race condition of concurrent handshakes
- added private-key legacy support to CLI parser (as outlined above, we strongly recommend that you define them as secret keys!!!1!)
- introduced Cachix for CI Nix caching (finally bearable feedack in time for more eager contributors)
- updated flake.lock
- belatedly updated from liboqs-0.7.2 to liboqs-0.8.0
- added shellcheck to CI
- updated rust/Cargo.lock dependencies


## v0.1.1 (2023-02-25)

### Features
- initial publication of the rosenpass tool, including associated whitepaper and artwork.

### Fixes
- proof-read the whitepaper
- added the nix-based development environment and CI
- disabled CI for Windows and aarch64-linux
- added automated release workflow

