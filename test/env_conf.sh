#!/bin/sh

set_up()
{
    set -x

    docker network create br-app
    docker network create br-store

    docker run -it --detach --name br --rm unikernel/mirage
    docker network disconnect bridge br
    docker network connect br-app br
    docker network connect br-store br

    APP_DNS=$(docker inspect br | python container_ip.py br-app)
    STORE_DNS=$(docker inspect br | python container_ip.py br-store)

    docker run -it --detach --name app   --rm --network br-app   --dns $APP_DNS   alpine:3.5 sh
    docker run -it --detach --name store --rm --network br-store --dns $STORE_DNS alpine:3.5 sh
}

tear_down()
{
    set -x

    docker stop app store br
    docker network rm br-app br-store
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
    *)
	echo "unknown command: env_config.sh" $@
	;;
esac
