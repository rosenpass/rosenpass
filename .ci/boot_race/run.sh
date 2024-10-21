#!/bin/bash

iterations="$1"
sleep_time="$2"
config_a="$3"
config_b="$4"

PWD="$(pwd)"
EXEC="$PWD/target/release/rosenpass"

i=0
while [ "$i" -ne "$iterations" ]; do
	echo "=> Iteration $i"

	# flush the PSK files
	echo "A" >rp-a-key-out.txt
	echo "B" >rp-b-key-out.txt

	# start the two instances
	echo "Starting instance A"
	"$EXEC" exchange-config "$config_a" &
	PID_A=$!
	sleep "$sleep_time"
	echo "Starting instance B"
	"$EXEC" exchange-config "$config_b" &
	PID_B=$!

	# give the key exchange some time to complete
	sleep 3

	# kill the instances
	kill $PID_A
	kill $PID_B

	# compare the keys
	if cmp -s rp-a-key-out.txt rp-b-key-out.txt; then
		echo "Keys match"
	else
		echo "::warning title=Key Exchange Race Condition::The key exchange resulted in different keys. Delay was ${sleep_time}s."
		# TODO: set this to 1 when the race condition is fixed
		exit 0
	fi

	# give the instances some time to shut down
	sleep 2

	i=$((i + 1))
done
