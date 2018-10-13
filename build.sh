#! /bin/sh

# compile code
echo "compiling..."
opam config exec -- jbuilder build bin/core_network.exe
cp ./_build/default/bin/core_network.exe ./core-network
echo "done compiling"
