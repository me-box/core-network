FROM ocaml/opam2:alpine as BUILDER

ENV OPAMYES=true

WORKDIR /core-network
ADD core-network.export core-network.export

RUN sudo apk update && sudo apk add alpine-sdk bash gmp-dev perl autoconf linux-headers zeromq-dev &&\
    opam switch 4.08 && opam update && \
    opam pin add -n mirage-net-psock.0.1.0 https://github.com/me-box/mirage-net-psock.git && \
    opam switch import core-network.export

ADD . .
RUN sudo chown opam: -R . && opam config exec -- dune build bin/core_network.exe


FROM alpine:3.6

WORKDIR /core-network
ADD start.sh start.sh
RUN apk update && apk add bash gmp-dev iptables iproute2 tcpdump
COPY --from=BUILDER /core-network/_build/default/bin/core_network.exe core-network

EXPOSE 8080

LABEL databox.type="core-network"

ENTRYPOINT ["./start.sh"]
