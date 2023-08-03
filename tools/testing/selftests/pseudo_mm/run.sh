#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
max=100

test_for() {
  exe=$1
  for i in `seq 1 $max`
  do
    $exe
    if [ "$?" -ne "0" ]; then
      echo "do anon_only in iteration $i failed"
      exit 1
    fi
  done
}

test_for "./anon_only"
test_for "./file_only"

exit 0
