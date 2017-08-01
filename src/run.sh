#!/bin/sh

set -x

docker cp config.ml br:/home/opam/bridge/
docker cp unikernel.ml br:/home/opam/bridge/

docker exec br sudo chown opam:opam /home/opam/bridge/config.ml
docker exec br sudo chown opam:opam /home/opam/bridge/unikernel.ml

docker exec br sh -c "cd /home/opam/bridge && opam config exec -- mirage configure -t unix"
docker exec br sh -c "cd /home/opam/bridge && opam config exec -- make"
