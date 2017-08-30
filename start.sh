#!/bin/bash

set -ex

sudo apk add iptables iproute2 tcpdump curl net-tools
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -F INPUT
sudo iptables -A INPUT -i lo -j ACCEPT

echo starting bridge...
/home/mebox/bridge -v &

echo starting connector driver...
/home/mebox/driver -v
