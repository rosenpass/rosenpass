# Rosenpass README

![Nix](https://github.com/rosenpass/rosenpass/actions/workflows/nix.yaml/badge.svg)
![QC](https://github.com/rosenpass/rosenpass/actions/workflows/qc.yaml/badge.svg)
![crates.io](https://img.shields.io/crates/v/rosenpass.svg)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/cargo/rosenpass)

This repository contains

1. A description of the [Rosenpass protocol](https://github.com/rosenpass/rosenpass/raw/papers-pdf/whitepaper.pdf)
2. The reference implementation of the protocol – the [rosenpass tool](./src)
3. A frontend integrating Rosenpass and WireGuard to create a vpn – the [rp frontend](./rp)
4. [Security analysis](./analysis) of the protocol using proverif

## Getting started

First, [install rosenpass](#Getting-Rosenpass). Then, check out the help functions of `rp` & `rosenpass`:

```sh
rp help
rosenpass help
```

Follow [quick start instructions](https://rosenpass.eu/#start) to get a VPN up and running.

## Software architecture

The [rosenpass tool](./src/) is written in Rust and uses liboqs[^liboqs] and libsodium[^libsodium]. The tool establishes a symmetric key and provides it to WireGuard. Since it supplies WireGuard with key through the PSK feature using Rosenpass+WireGuard is cryptographically no less secure than using WireGuard on its own ("hybrid security"). Rosenpass refreshes the symmetric key every two minutes.

As with any application a small risk of critical security issues (such as buffer overflows, remote code execution) exists; the Rosenpass application is written in the Rust programming language which is much less prone to such issues. Rosenpass can also write keys to files instead of supplying them to WireGuard With a bit of scripting the stand alone mode of the implementation can be used to run the application in a Container, VM or on another host. This mode can also be used to integrate tools other than WireGuard with Rosenpass.

The [`rp`](./rp) tool written in bash makes it easy to create a VPN using WireGuard and Rosenpass.

`rp` is easy to get started with but has a few drawbacks; it runs as root, demanding access to both WireGuard
and Rosenpass private keys, takes control of the interface and works with exactly one interface. If you do not feel confident about running Rosenpass as root, you should use the stand-alone mode to create a more secure setup using containers, jails, or virtual machines.

### Networking & ports

rp allocates two UDP ports; if port N is specified for rosenpass, it will allocate port N+1 for WireGuard.

Like WireGuard, Rosenpass does not enforce any separation between clients and servers.
If you do not specify the `listen` option, Rosenpass and WireGuard will choose random ports; this is _client mode_.
If you do not specify `endpoint`, Rosenpass will not try to connect to the peer and instead wait for connections from peers. This is _server mode_.
You may specify both. Leaving out both is not forbidden but also not very useful.

## Security analysis

<!-- Currently, a symbolic analysis in proverif asserts various properties for the Rosenpass protocol. Further on, a proof of the cryptographic promises based on cryptoverif is in the process of being made. -->

We are working on a cryptographic proof of security, but we already provide a symbolic analysis using proverif as part of the software package. You can run the security analysis using the nix package manager which handles installing the dependencies or you can call the [`./analyze.sh`](https://github.com/rosenpass/rosenpass/blob/main/analyze.sh) script directly. In this case, you need to ensure that `proverif`, `graphviz`, `awk`, and `cpp` are installed on your system.

```sh
   (nix) $ nix build .#proof-proverif --print-build-logs
(manual) $ ./analyze.sh
```

The analysis is implemented according to modern software engineering principles: Using the C preprocessor, we where able to split the analysis into multiple files and uses some meta programming to avoid repetition.
The code uses a variety of optimizations to speed up analysis such as using secret functions to model trusted/malicious setup. We split the model into two separate entry points which can be analyzed in parallel. Each is much faster than both models combined.
A wrapper script provides instant feedback about which queries execute as expected in color: A red cross if a query fails and a green check if it succeeds.

[^liboqs]: https://openquantumsafe.org/liboqs/
[^libsodium]: https://doc.libsodium.org/
[^wg]: https://www.wireguard.com/
[^pqwg]: https://eprint.iacr.org/2020/379
[^pqwg-statedis]: Unless supplied with a pre-shared-key, but this defeats the purpose of a key exchange protocol
[^wg-statedis]: https://lists.zx2c4.com/pipermail/wireguard/2021-August/006916.htmlA

# Getting Rosenpass

Rosenpass is packaged for more and more distributions, maybe also for the distribution of your choice?

[![Packaging status](https://repology.org/badge/vertical-allrepos/rosenpass.svg)](https://repology.org/project/rosenpass/versions)

## Compile it yourself

You can also compile Rosenpass yourself. This gives you the advantage of ensuring that you use Rosenpass as you find the source code in Git.

1. Install the dependencies. Under Debian, you can do this with the following command: `sudo apt-get --yes install libsodium-dev libclang-dev cmake pkg-config git build-essential`
2. If you want to use Rosenpass with WireGuard, install WireGuard. On Debian, you can do this with the following command: `sudo apt-get --yes install wireguard`
3. Install Rust >= 1.64.0 (as of 07.2023). For this you can use [Rustup](https://rustup.rs/), for example.
4. Clone the Git Repository: `git clone https://github.com/rosenpass/rosenpass.git`
5. Change to the Rosenpass directory: `cd rosenpass`
6. Switch to the version you want to install. Without switching, you will install and compile the dev version: `git checkout v0.1.1`
7. Compile Rosenpass: `cargo build --release` This may take a while.
8. Install Rosenpass: `sudo install target/release/rosenpass /usr/local/bin`
9. If you want the Rosenpass helper `rp`, install it with: `sudo install rp /usr/local/bin`

That's it. You have now downloaded, compiled and installed Rosenpass.

## Installation via binary files

If Rosenpass is not yet in your distribution, you can see if you can download it manually.

1. Download the desired version for your operating system from the [release](https://github.com/rosenpass/rosenpass/releases/).
2. Unzip the file. On Linux you can use tar for this: `tar xf rosenpass-x86_64-linux-0.1.1.tar`
3. Install Rosenpass: `sudo install bin/rosenpass /usr/local/bin`
4. If you want the Rosenpass helper `rp`, install it with: `sudo install bin/rp /usr/local/bin`
5. Delete the downloaded files: `rm -r rosenpass-x86_64-linux-0.1.1.tar bin/`

That's it. You have now downloaded and installed Rosenpass.

# Supported by

Funded through <a href="https://nlnet.nl/">NLNet</a> with financial support for the European Commission's <a href="https://nlnet.nl/assure">NGI Assure</a> program.
