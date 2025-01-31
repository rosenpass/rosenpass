# Supply Chain Protection

The CI for this repository uses the following tools to protect the supply chain:

- [cargo-vet](https://github.com/mozilla/cargo-vet): vets dependencies based on existing audits with the aim of incrementally using fewer and fewer unaudited dependencies.
- [cargo-deny](https://github.com/EmbarkStudios/cargo-deny): checks for unwanted licenses, crates, and other security issues.
- [cargo-supply-chain](https://github.com/rust-secure-code/cargo-supply-chain): generates reports on dependencies and their authors.

Below, we briefly explain how to configure these tools and how to make appropriate adjustments when dependencies change.

## cargo-vet

`cargo-vet` vets dependencies based on performed audits. In order to avoid redundant work, it encourages the use of already
performed audits by trusted organizations or people. As of now, we trust audits performed by the
[actix team](https://raw.githubusercontent.com/actix/supply-chain/main/audits.toml), the [bytecode-alliance](https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml)
[embark-studios](https://raw.githubusercontent.com/EmbarkStudios/rust-ecosystem/main/audits.toml),
[fermyon](https://raw.githubusercontent.com/fermyon/spin/main/supply-chain/audits.toml),
[google](https://raw.githubusercontent.com/google/supply-chain/main/audits.toml),
the [ISRG](https://raw.githubusercontent.com/divviup/libprio-rs/main/supply-chain/audits.toml),
the [mozilla team](https://raw.githubusercontent.com/mozilla/cargo-vet/main/audits.toml),
and the [ZCash foundaton](https://raw.githubusercontent.com/zcash/rust-ecosystem/main/supply-chain/audits.toml).
Since, as of now, only a minority of crates have been audited, the tool aims at incrementally using fewer and fewer unaudited dependencies by initially exempting all dependencies
from the need to be audited for the CI to pass. When more and more crates are audited, the tool prompts to reevaluate
the list of exemptions and remove as many as possible.

### Configuration

The configuration files for cargo-vet are located in the `supply-chain` directory. The central configuration file is
`config.toml`, where the lst of trusted organizations and the list of exemptions are defined.

### Adding new dependencies

Make sure to [install cargo vet](https://mozilla.github.io/cargo-vet/install.html) first.
Then, when adding new dependencies, run `cargo vet suggest` before committing. If the dependency is not safe-to-deploy,
add it to the exemptions in the file `supply-chain/config.toml`.

For all further configration options, please refer to the [cargo-vet documentation](https://mozilla.github.io/cargo-vet/).

## cargo-deny

`cargo-deny` checks for unwanted licenses, crates, and other security issues. It is configured in the file `deny.toml`.

### Licenses

The only allowed licenses are the MIT license, the Apache-2.0 license, Apache-2.0 license WITH LLVM-exception,
BSD-3-Clause license and the ISC license. All other licenses are banned. An exception is made for the
`unicode-ident`-crate, for which we allow the Unicode-DFS-2016 license.

### Security vulnerabilities

The tool checks for security vulnerabilities in dependencies. If a vulnerability is found, the CI will fail. If you must,
you can add exceptions in the `deny.toml` file, but this should only be a last resort.

### Adding new dependencies

Make sure to [install cargo deny](https://embarkstudios.github.io/cargo-deny/) first. Then, when adding new dependencies,
run `cargo deny check` before committing. If there are issues wth the dependency reported by `cargo deny check`, you
should try to resolve it appropriately. If this is not possible thoroughly consider if the dependency is necessary and
an exception should be made in the `deny.toml` file.

For all further configration options, please refer to the [cargo-deny documentation](https://embarkstudios.github.io/cargo-deny/).

## cargo-supply-chain

`cargo-supply-chain` generates reports on dependencies and their authors. These reports should be reviewed regularly.
However, they will not cause the CI to fail.
