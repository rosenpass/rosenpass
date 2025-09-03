# Integration Tests

This directory contains integration tests for rosenpass in the form of a nix flake. Put simply, in order to run the integration tests for the main branch as they are on github right now, just run the following on a linux machine with nix installed and flakes enabled:

```
nix flake check
```

## Overview

The integration tests recognize two rosenpass versions, a new version and an old version. If not adapted, both are set to the version of the current main branch of rosenpass on github. We describe below how to change this.
All integration tests install rosenpass on virtual machines, run the key exchange, create a connection via wireguard that uses rosenpass and then checks whether all peers can ping each other via wireguard. Overall there are four integration tests:

- `basicConnectivity` -- This test only uses the new rosenpass version and checks whether the key exchange between two peers works such that they can ping each other.
- `backwardClient` -- This test is the same as the `basicConnectivity` test, but with the client using the old rosenpass version.
- `backwardServer` -- This test is the same as the `backwardClient` test, but with the server using the old rosenpass version.
- `multiPeer` -- This test again only uses the new rosenpass version, but with three peers. The first peer acts as a server towards the other two peers. The second peer acts as a client towards the first peer and as a server towards the third peer. The third peer acts as a client towards all peers.

## Testing specific versions

You can specify specific versions of rosenpass to test compatability. The proper way to do so is by overriding the respective inputs to the nix flake. As an example, say you want to test the compatability of your local version of rosenpass with the branch `new-feature` on github. You can achieve this by running the following command:

```
nix flake check  --override-input rosenpass-old ../../ --override-input rosenpass-new github:rosenpass/rosenpass/new-feature
```

## Usage in the CI

In the CI, the integration tests are used differently, depending on whether the CI run is triggered by a push to the main branch or by a pull request. If the CI run is triggered by a pull request, then the result of merging the main branch and the PR branch is set as the new version and the current state of the main branch is set as the old version. For push events, the CI is only triggered if the push is onto the main branch. In that case, the state before the push event is considered the old version and the state after the push event is considered as the new version.
