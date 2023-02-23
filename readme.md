# Rosenpass README

This repository contains

1. A description of the [Rosenpass protocol](https://github.com/rosenpass/rosenpass/raw/papers-pdf/whitepaper.pdf)
2. The reference implementation of the protocol – the [rosenpass tool](./src)
3. A frontend integrating Rosenpass and WireGuard to create a vpn – the [rp frontend](./rp)
4. [Security analysis](./analysis) of the protocol using proverif

## Getting started

[how to install nix]
[how to build with nix]
[how to build without nix]

```sh
rp help
rosenpass help
```

Follow [quickstart instructions – TBD]() to get a VPN up and running.

## Software architecture

The [rosenpass tool](./src/) is written in Rust and uses liboqs[^liboqs] and libsodium[^libsodium]. The tool establishes a symmetric key and provides it to WireGuard. Since it supplies WireGuard with key through the PSK feature using Rosenpass+WireGuard is cryptographically no less secure than using WireGuard on its own ("hybrid security"). Rosenpass refreshes the symmetric key every two minutes.

As with any application a small risk of critical security issues (such as buffer overflows, remote code execution)  exists; the Rosenpass application is written in the Rust programming language which is much less prone to such issues. Rosenpass can also write keys to files instead of supplying them to WireGuard With a bit of scripting the stand alone mode of the implementation can be used to run the application in a Container, VM or on another host. This mode can also be used to integrate tools other than WireGuard with Rosenpass.

The [`rp`](./rp) tool written in bash makes it easy to create a VPN using WireGuard and Rosenpass.

`rp` is easy to get started with but has a few drawbacks; it runs as root, demanding access to both WireGuard
and Rosenpass private keys, takes control of the interface and works with exactly one interface. If you do not feel confident about running Rosenpass as root, you should use the stand-alone mode to create a more secure setup using containers, jails, or virtual machines.

### Networking & ports

rp allocates two UDP ports; if port N is specified for rosenpass, it will allocate port N+1 for WireGuard.

Like WireGuard, Rosenpass does not enforce any separation between clients and servers.
If you do not specify the `listen` option, Rosenpass and WireGuard will choose random ports; this is *client mode*.
If you do not specify `endpoint`, Rosenpass will not try to connect to the peer and instead wait for connections from peers. This is *server mode*.
You may specify both. Leaving out both is not forbidden but also not very useful.

## Security analysis

<!-- Currently, a symbolic analysis in proverif asserts various properties for the Rosenpass protocol. Further on, a proof of the cryptographic promises based on cryptoverif is in the process of being made. -->

We are working on a cryptographic proof of security, but we already provide a symbolic analysis using proverif as part of the software package. You can run the security analysis using the nix package manager which handles installing the dependencies or you can call the [`./analyze.sh`](https://github.com/rosenpass/rosenpass/blob/main/analyze.sh) script directly. In this case, you need to ensure that `proverif`, `graphviz`, `awk`, and `cpp` are installed on your system.

```sh
   (nix) $ nix build .#proof-proverif --print-build-logs
(manual) $ ./analyze.sh
```

The analysis is implemented according to modern software engineering principles: Using the C preprocessor, we where able to split the analysis into multiple files and uses some metaprogramming to avoid repetition.
The code uses a variety of optimizations to speed up analysis such as using secret functions to model trusted/malicious setup. We split the model into two separate entry points which can be analyzed in parallel. Each is much faster than both models combined.
A wrapper script provides instant feedback about which queries execute as expected in color: A red cross if a query fails and a green check if it succeeds.

[^wg]: https://www.wireguard.com/
[^pqwg]: https://eprint.iacr.org/2020/379
[^pqwg-statedis]: Unless supplied with a pre-shared-key, but this defeates the purpose of a key exchange protocol
[^wg-statedis]: https://lists.zx2c4.com/pipermail/wireguard/2021-August/006916.html
