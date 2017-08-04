#!/bin/sh

set_up()
{
    set -x

    docker network create br-app
    docker network create br-store
    docker network create br-noop

    #start bridge
    docker run -it --detach --name br --rm --cap-add NET_ADMIN \
	   -v /home/qli/workspace/databox-bridge/src:/home/mebox/src:rw seveneng/opam:with-mirage
    docker network disconnect bridge br
    docker network connect br-app br
    docker network connect br-store br
    docker network connect br-noop br

    APP_DNS_GW=$(docker inspect br | python container_ip.py br-app)
    STORE_DNS_GW=$(docker inspect br | python container_ip.py br-store)
    NOOP_DNS_GW=$(docker inspect br | python container_ip.py br-noop)

    #start app
    docker run -it --detach --name app   --rm --network br-app \
	   --dns $APP_DNS_GW   --cap-add NET_ADMIN alpine:3.5 sh
    docker exec app ip route del default
    docker exec app ip route add default via $APP_DNS_GW

    #start store
    docker run -it --detach --name store --rm --network br-store \
	   --dns $STORE_DNS_GW --cap-add NET_ADMIN alpine:3.5 sh
    docker exec store ip route del default
    docker exec store ip route add default via $STORE_DNS_GW

    #start noop
    docker run -it --detach --name noop --rm --network br-noop \
	   --dns $NOOP_DNS_GW --cap-add NET_ADMIN alpine:3.5 sh
    docker exec noop ip route del default
    docker exec noop ip route add default via $NOOP_DNS_GW

}

tear_down()
{
    set -x

    docker stop app store noop br
    docker network rm br-app br-store br-noop
}


run()
{
    set -x

    docker exec br rm -rf /home/opam/src
    docker cp ../src br:/home/opam/src/
    docker exec br sudo chown opam:opam -R /home/opam/src
    docker exec br sh /home/opam/src/start.sh
}

case $1 in
    "up")
	echo "setting up..."
	set_up
	;;
    "down")
	echo "tearing down..."
	tear_down
	;;
    "run")
	echo "copy and build..."
	run
	;;
    *)
	echo "unknown command: env_config.sh" $@
	;;
esac
