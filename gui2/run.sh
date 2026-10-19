#!/bin/env bash
# usage: ./run.sh <iface> <gnb-mac> [ue-mac]
#   e.g. ./run.sh sfp1 bc:24:11:ec:73:d3 bc:24:11:aa:bb:cc
#
# Naming the UE matters when more than two devices sit on the mirror:
# without it every non-gNB sender is folded into the uplink accumulator.

./build/src/split_scope "$@"
