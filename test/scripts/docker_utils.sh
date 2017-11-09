#!/bin/bash

# ip_on_net <container> <network>
function ip_on_net {
  NET_ID=$(docker network inspect ${2} --format "{{.Id}}")
  IP_FORMAT="{{range .NetworkSettings.Networks}}{{if eq \"${NET_ID}\" .NetworkID}}{{.IPAddress}}{{end}}{{end}}"
  docker inspect ${1} --format "${IP_FORMAT}"
}

# !!! NEED $CN
# install <image> <service> [<cmd>]
function install {
  NET=${2}-core-network
  docker network create -d overlay --internal --attachable ${NET} >/dev/null
  docker network connect ${NET} ${CN}

  if [ -z "${3}" ]; then
    CMD="sleep 8h"
  else
    CMD=${3}
  fi

  docker service create --name ${2} --replicas 1 --endpoint-mode dnsrr ${DARGS}\
    --network ${NET} --dns $(ip_on_net ${CN} ${NET}) ${1} ${CMD} >/dev/null 2>&1
}

# !!! NEED $CN
# uninstall <service>
function uninstall {
  NET=${1}-core-network
  docker service rm ${1} >/dev/null
  docker network disconnect ${NET} ${CN}
  docker network rm ${NET} >/dev/null

  DANGLING=0
  while [ "$DANGLING" == "0" ]; do
    sleep 1s
    docker network inspect ${NET} >/dev/null 2>&1
    DANGLING=$?
  done
}

# container <service>
# return <container>
function container {
  NAME=
  while [ -z "$NAME" ]; do
    sleep 1s
    NAME=$(docker ps --filter "name=${1}" --format "{{.Names}}")
  done
  echo ${NAME}
}
