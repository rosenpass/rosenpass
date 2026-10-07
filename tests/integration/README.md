# Integration Tests

This directory contains the integration tests for rosenpass. They are exposed as Nix flake checks. In order to run the integration tests as they are on github right now, just run the following on a linux machine with nix installed and flakes enabled:

```
nix build .#checks.x86_64-linux.integration
```

(Replace `x86_64-linux` with your system. Alternatively, `nix flake check` runs the integration tests together with all other checks of the rosenpass flake.)

## Overview

The integration tests recognize two rosenpass versions, a new version and an old version. The new version is always the state of your local checkout. The old version is the rosenpass version v0.2.3 by default; we describe below how to change this.
All integration tests install rosenpass on virtual machines, run the key exchange, create a connection via wireguard that uses rosenpass and then checks whether all peers can ping each other via wireguard. Overall there are four integration tests:

- `basicConnectivity` -- This test only uses the new rosenpass version and checks whether the key exchange between two peers works such that they can ping each other.
- `backwardClient` -- This test is the same as the `basicConnectivity` test, but with the client using the old rosenpass version.
- `backwardServer` -- This test is the same as the `backwardClient` test, but with the server using the old rosenpass version.
- `multiPeer` -- This test again only uses the new rosenpass version, but with three peers. The first peer acts as a server towards the other two peers. The second peer acts as a client towards the first peer and as a server towards the third peer. The third peer acts as a client towards all peers.

## Testing specific versions

You can specify the old version of rosenpass to test compatibility against. The proper way to do so is by overriding the `rosenpassOld` input of the nix flake. The new version is always the state of your local checkout; if you want to test a specific version as the new version, check it out locally first. Example (test against `main` branch):

```
nix build .#checks.x86_64-linux.integration --override-input rosenpassOld github:rosenpass/rosenpass/main
```

## Usage in the CI

In the CI, the old rosenpass version is chosen depending on whether the CI run is triggered by a push to the main branch or by a pull request. If the CI run is triggered by a pull request, then the result of merging the main branch and the PR branch is the new version and the current state of the main branch is the old version. For push events, the CI is only triggered if the push is onto the main branch. In that case, the state before the push event is the old version and the state after the push event is the new version. Additionally, the CI tests against further old versions from the test matrix in `.github/workflows/integration.yml`, such as the `main` branch and the stable `v0.2.3`.
