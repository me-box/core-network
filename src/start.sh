#!/bin/sh

set -x

sudo iptables -F INPUT
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

opam pin add -n -y mirage-net-unix https://github.com/sevenEng/mirage-net-psock.git

cd /home/opam/src
eval `opam config env`
mirage configure -t unix
#make depends


substitute()
{
    ETHIF=$1
    IP=$2

    FUNC='Ipaddr.V4.Prefix.of_address_string_exn '

    sed -i -e "0,/(Key_gen.interface ())/s/(Key_gen.interface ())/$ETHIF/" main.ml
    sed -i -e "0,/(Key_gen.ipv4 ())/s/(Key_gen.ipv4 ())/$FUNC$IP/" main.ml
}


substitute '"eth1"' '"172.18.0.2\/16"'
substitute '"eth2"' '"172.19.0.2\/16"'
substitute '"eth3"' '"172.20.0.2\/16"'


#sed -i -e '0,/(Key_gen.interface ())/s/(Key_gen.interface ())/"eth1"/' main.ml
#sed -i -e '0,/(Key_gen.interface ())/s/(Key_gen.interface ())/"eth2"/' main.ml
#sed -i -e '0,/(Key_gen.interface ())/s/(Key_gen.interface ())/"eth3"/' main.ml

make

sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT -i lo -j ACCEPT
