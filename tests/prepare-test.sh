#!/usr/bin/env bash

set -euxo pipefail

< /etc/rosenpass/example.toml  \
  sed 's@example@server@' > /etc/rosenpass/server.toml

< /etc/rosenpass/example.toml \
  sed 's@listen.*@@' |
  sed 's@client@server@' |
  sed 's@example@client@' |
  sed 's@fc00::2@fc00::1@' |
  sed 's@fc00::1/64@fc00::2/64@' > /etc/rosenpass/client.toml

echo 'endpoint = "[::1]:51821"' >> /etc/rosenpass/client.toml

rp genkey server-sk
rp pubkey server-sk server-pk

rp genkey client-sk
rp pubkey client-sk client-pk

mkdir -p /etc/rosenpass/server/peers/client
mkdir -p /etc/rosenpass/client/peers/server

cp server-sk/{pqpk,pqsk,wgsk} /etc/rosenpass/server/
cp client-sk/{pqpk,pqsk,wgsk} /etc/rosenpass/client/

cp client-pk/{pqpk,wgpk} /etc/rosenpass/server/peers/client
cp server-pk/{pqpk,wgpk} /etc/rosenpass/client/peers/server
