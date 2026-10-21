#!/bin/env bash
# usage: ./run.sh <iface> [mac=label ...]
#
# Every distinct source MAC sending eCPRI gets its own lane, discovered as
# it appears. Naming is optional: it fixes a sender's lane position, colour
# and label instead of letting arrival order decide.
#
#   ./run.sh sfp1
#   ./run.sh sfp1 bc:24:11:ec:73:d3=gNB-wnbox4 \
#                 bc:24:11:aa:bb:cc=UE-wnbox7  \
#                 00:0a:35:11:22:33=FPGA-gNB

./build/src/split_scope3 "$@"
