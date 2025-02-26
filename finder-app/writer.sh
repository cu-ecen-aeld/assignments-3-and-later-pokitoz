#!/bin/sh -e

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: Missing arguments"
    exit 1
fi

writefile="$1"
writestr="$2"

mkdir -p $(dirname "$writefile")
touch "$writefile"
echo "$writestr" > $writefile
if [ $? -ne 0 ]; then
    echo "Error: Could not create file"
    exit 1
fi
exit 0
