#!/bin/bash

set -e

#sudo apk add iptables iproute2 tcpdump curl net-tools

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -F INPUT
iptables -A INPUT -i lo -j ACCEPT

echo starting bridge...
./bridge
