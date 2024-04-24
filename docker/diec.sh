#!/bin/bash
# This will simply take the argument passed to it,
# parse the directory and bind it as a read-only mount point on the container
# and pass in the filename as the argument to diec.sh
# This assumes file target is last argument!

# Build with:
# docker build . -t horsicq:diec

TARGET="${@: -1}"  # last argument is target file
INPUT_DIR=$(cd $(dirname "$TARGET") && pwd -P)
INPUT_FILE=$(basename $TARGET)


if [ "$#" -eq 0 ]; then
  docker run  -i horsicq:diec
elif [ "$#" -eq 1 ]; then
  docker run --rm --volume "$INPUT_DIR":/input:ro -i horsicq:diec "/input/$INPUT_FILE";
else
  docker run --rm --volume "$INPUT_DIR":/input:ro -i horsicq:diec "/input/$INPUT_FILE" "${@:1:$#-1}";
fi
