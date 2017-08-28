FROM alpine:3.5

RUN apk update && apk upgrade &&\
    apk add sudo &&\
    adduser -S mebox &&\
    echo 'mebox ALL=(ALL:ALL) NOPASSWD:ALL' > /etc/sudoers.d/mebox &&\
    chmod 440 /etc/sudoers.d/mebox &&\
    chown root:root /etc/sudoers.d/mebox &&\
    sed -i.bak 's/^Defaults.*requiretty//g' /etc/sudoers

USER mebox
WORKDIR /home/mebox

ADD . core-bridge

RUN sudo apk add opam bash
RUN cd core-bridge && ./install.sh

CMD ["bash", "/home/mebox/core-bridge/start.sh"]