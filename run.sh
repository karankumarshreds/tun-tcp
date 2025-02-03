#!/bin/bash

proto="${1:-ICMP}"

sudo ifconfig utun69 192.168.69.1 192.168.69.2 up

if [ "$proto" = "ICMP" ]; then
    echo "Using default protocol: ICMP"
    ping -c 3 192.168.69.2 # for ICMP
elif [ "$proto" = "TCP" ]; then
    echo "Using protocol: TCP"
    echo "hello" | nc -v -n 192.168.69.2 12345
fi
