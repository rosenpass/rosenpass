#!/usr/bin/env bash

set -e

info(){
  echo -e "\e[1;32m$1\e[0m"
}

error(){
  echo -e "\e[1;31m$1\e[0m"
}

MISSING_VARS=()
if [ -z ${USERNAME+x} ]; then
  MISSING_VARS+=('USERNAME')
fi

if [ -z ${PASSWORD+x} ]; then
  MISSING_VARS+=('PASSWORD')
fi

if [ -z ${BENCH_INTERFACE+x} ]; then
  MISSING_VARS+=('BENCH_INTERFACE')
fi

if [[ ${#MISSING_VARS[@]} != 0 ]]; then
  error "the following variables are missing: ${MISSING_VARS[*]}"
  exit 1
fi


# find the peer
info "scanning for peer"
ping -c 1 "ff02::1%$BENCH_INTERFACE"
ip -family inet6 -json neigh show dev "$BENCH_INTERFACE" > neighbours.json

# we expect exactly one neighbour
if [[ "$(dasel select --file neighbours.json --length)" != 1 ]]
then
  error "we expect exactly one reachable peer, but we found the following"
  dasel select --file neighbours.json
  exit 1
fi

if [[ "$(dasel select --file neighbours.json '[0].state.[0]' --plain)" == "FAILED" ]]
then
  error "our neighbour is not reachable"
  dasel select --file neighbours.json
  exit 1
fi


# extract peer's IP, concatenated with the respective interface
PEER_IP="$(dasel select --file neighbours.json '[0].dst' --plain)%$BENCH_INTERFACE"
PEER_MAC=$(dasel select --file neighbours.json '[0].lladdr' --plain)
info "peer found; MAC = $PEER_MAC , IP = $PEER_IP"

# find link MAC
ip --json link show dev "$BENCH_INTERFACE" > link.json
OWN_MAC=$(dasel select --file link.json '[0].address' --plain)

# check the peer is pingable
ping -c 10 -i 0.1 "$PEER_IP"

# determine own role
OWN_UPTIME=$(cut --delimiter=' ' --fields=1 /proc/uptime)
PEER_UPTIME=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USERNAME@$PEER_IP" cut --delimiter=' ' --fields=1 /proc/uptime)
OWN_SERVERNESS="$OWN_UPTIME $OWN_MAC"
PEER_SERVERNESS="$PEER_UPTIME $PEER_MAC"
SERVER_IDENTITY=$(echo -e "$OWN_SERVERNESS\n$PEER_SERVERNESS" | sort --numeric-sort | tail --lines 1 | cut -d' ' --fields=2)
info "found $SERVER_IDENTITY to be the server"

# setup instrumentation

# $1 = binary to check
# $2 = function to search for
function_address(){
  nm --demangle=rust "$1" --format=sysv | grep "^$2\s*|" | cut -d'|' -f2
}

ROSENPASS_BINARY=$(readlink -f $(which rosenpass))

perf probe --exec "$ROSENPASS_BINARY" --add "rg_started=main"
perf probe --exec "$ROSENPASS_BINARY" --add "rg_exchange_done=0x$(function_address "$ROSENPASS_BINARY" "rosenpass::AppServer::output_key")"

pushd /sys/kernel/debug/tracing
echo "p $ROSENPASS_BINARY:0x$(function_address "$ROSENPASS_BINARY" "main")"" > uprobe_events

cat /sys/kernel/debug/tracing/uprobe_events

if [[ "$OWN_MAC" == "$SERVER_IDENTITY" ]]
then
  info "i identify as server"

  info "measuring datarates"
  iperf --client "$PEER_IP" --bidir

  info "generating key pair"
  rosenpass keygen private-key server-key public-key server-key.pub

  info "distributing public-key"
  sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    server-key.pub "$USERNAME@$PEER_IP:$PWD/"

  info "waiting for client-key.pub"
  while [ ! -f clent-key.pub ]; do sleep 0.1; done

  info "public key received, launching rosenpass"
  rosenpass exchange private-key server-key public-key server-key.pub \
    listen ::1:17800 verbose peer public-key client-key.pub

elif [[ "$PEER_MAC" == "$SERVER_IDENTITY" ]]
then
  info "i identify as client"

  info "generating key pair"
  rosenpass keygen private-key client-key public-key client-key.pub

  info "distributing public-key"
  sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    client-key.pub "$USERNAME@$PEER_IP:$PWD/"


  info "waiting for server-key.pub"
  while [ ! -f clent-key.pub ]; do sleep 0.1; done

  info "public key received, launching rosenpass"
  rosenpass exchange private-key client-key public-key client-key.pub verbose \
    peer server-key.pub endpoint "$PEER_IP:17800" outfile
else
  error "no server identity found, terminating"
  exit 1
fi
