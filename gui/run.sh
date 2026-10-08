#!/bin/env bash
# usage: ./run.sh <iface> <dl-src-mac>
#   e.g. sudo ./run.sh sfp1 bc:24:11:ec:73:d3

./build/src/imgui_app "$@"
