#!/bin/bash

set -e

sudo apk add m4 perl autoconf gmp-dev ncurses-dev alpine-sdk linux-headers

opam init -y
opam update
eval `opam config env`

opam pin add -n mirage-net-unix https://github.com/sevenEng/mirage-net-psock.git
opam pin add -n hashcons https://github.com/sevenEng/ocaml-hashcons.git

echo Import OPAM packages...
opam switch import -y bridge.export
eval `opam config env`

echo Compile sources...
cd /home/mebox/core-bridge/src
sudo chown mebox: -R .
jbuilder build bridge.exe
ln -s `pwd`/_build/default/bridge.exe /home/mebox/bridge

cd /home/mebox/core-bridge/driver
sudo chown mebox: -R .
jbuilder build driver.exe
ln -s `pwd`/_build/default/driver.exe /home/mebox/driver



