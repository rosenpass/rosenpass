#!/bin/bash

iterations=$1
sleep_time=$2

PWD=$(pwd)
EXEC=$PWD/target/release/rosenpass
LOGS=$PWD/output/logs

mkdir -p output/logs

run_command() {
  local file=$1
  local log_file="$2"
  ($EXEC exchange-config $file 2>&1 | sed "s/^/[$2] /" | tee -a $log_file) &
  echo $!
}

pids=()

(cd output/dut && run_command "configs/dut-$iterations.toml" "dut.log") & piddut=$!
for (( x=0; x<$iterations; x++ )); do
  (cd output/ate && run_command "configs/ate-$x.toml" "ate-$x.log") & pids+=($!)
done

sleep $sleep_time

lsof -i :9999 | awk 'NR!=1 {print $2}' | xargs kill

for (( x=0; x<$iterations; x++ )); do
    port=$((x + 50000))
    lsof -i :$port | awk 'NR!=1 {print $2}' | xargs kill
done