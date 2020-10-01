#!/bin/bash

function mod_refs() {
    local count=$(lsmod | grep ^netgpu | awk '{$s += $3} END {print $s}')
    echo $(($count + 0))
}

function check() {
    local cmd="$*"
    local leak err

    start=$(mod_refs)

    out=$($cmd)
    RET=$?

    end=$(mod_refs)

    if [ $start -ne $end ]; then
        leak=$(echo "module refcount leak: $start -> $end")
    fi

    if [ $RET -ne 0 ]; then
        err=$(echo "$cmd failed with error $RET")
    fi

    if [[ $leak || $err ]]; then
        echo FAILED: $cmd
        echo $out
        echo $leak
        echo $err
        exit 1
    fi
}

function test_suite() {
    local args="$1"

    check ./memarea $args
    check ./context $args
    check ./dmamap $args
    check ./socket $args
    check ./netqueue $args
}

test_suite

cuda=$(test -e /usr/local/cuda/bin/nvcc && echo 1)
if [[ $cuda ]]; then
     test_suite -m
fi
