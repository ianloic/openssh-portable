#!/bin/bash

# A trivial helper script to concat authorized_key files

if [[ $# -lt 2 ]]; then
  echo "$0 <output-file> <input-files>..."
  exit 1
fi

cat "${@:2}" > $1
