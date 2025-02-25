#!/bin/bash -e

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Please provide the directory path and the search string"
    exit 1
fi

if [ ! -d "$1" ]; then
    echo "The directory path provided is not a directory"
    exit 1
fi

filesdir=$1
searchstr=$2

# Count the number of files in the directory and all subdirectories
num_files=$(find $filesdir -type f | wc -l)
num_grep_files=$(grep -r $searchstr $filesdir | wc -l)

echo "The number of files are $num_files and the number of matching lines are $num_grep_files"
exit 0
