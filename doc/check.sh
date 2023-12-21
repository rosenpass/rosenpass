#!/usr/bin/env bash

# We have to filter this STYLE error out, because it is very platform specific
OUTPUT=$(mandoc -Tlint "$1" | grep --invert-match "STYLE: referenced manual not found")

if [ -z "$OUTPUT" ]
then
	exit 0
else
	echo "$1 is malformatted, check mandoc -Tlint $1"
	echo "$OUTPUT"
	exit 1
fi
