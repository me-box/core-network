#!/bin/bash

set -ex

mask2cdr ()
{
    # Assumes there's no "255." after a non-255 byte in the mask
    local x=${1##*255.}
    set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
    x=${1%%$3*}
    echo $(( $2 + (${#x}/4) ))
}

ips=($(ifconfig | sed -En 's/127.0.0.1//;s/169.//;s/.inet (addr:)?(([0-9]+.){3}[0-9]+).*/\2/p'))
INTF=${ips[0]}

masks=($(ifconfig | sed -En 's/127.0.0.1//;s/169.//;s/.inet (addr:)?.*Mask:(([0-9]+.){3}[0-9]+)/\2/p'))
MASK=$(mask2cdr ${masks[0]})

if [ "${#ips[@]}" -gt "1" ]; then
    echo More than one IP found!
fi

sudo apk add iptables iproute2 tcpdump curl net-tools
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -F INPUT
sudo iptables -A INPUT -i lo -j ACCEPT

echo using $INTF to start bridge...
/home/mebox/bridge $INTF -v &

if [ -d "/home/mebox/connector_eth0" ]; then
    rm -rf /home/mebox/connector_eth0
fi

cp -R /home/mebox/core-bridge/driver/connector /home/mebox/connector_eth0
sed -E 's/%%PATH%%/\/home\/mebox\/connector_eth0/' </home/mebox/core-bridge/driver/start.sh.tmpl \
    >/home/mebox/connector_eth0/start.sh
sed -E "s|%%DEVICE%%|eth0|;s|%%ADDRESS%%|$INTF/$MASK|" </home/mebox/core-bridge/driver/config.ml.tmpl \
    >/home/mebox/connector_eth0/config.ml

cd /home/mebox/connector_eth0
sh start.sh

echo starting connector driver...
/home/mebox/driver -v
