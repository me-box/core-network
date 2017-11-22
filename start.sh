#!/bin/bash

set -e

#sudo apk add iptables iproute2 tcpdump curl net-tools

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -F INPUT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT  -p udp --sport 53 -j ACCEPT
iptables -A INPUT  -p tcp --sport 53 -j ACCEPT


echo starting core-network...
./core-network $@
