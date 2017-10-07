#FROM databoxsystems/base-image-ocaml:alpine-3.4_ocaml-4.04.2 as BUILDER
FROM ocaml/opam:alpine-3.6_ocaml-4.04.2 as BUILDER

WORKDIR /core-bridge
ADD bridge.export bridge.export

RUN sudo apk update && sudo apk add alpine-sdk bash gmp-dev perl autoconf linux-headers &&\
    opam remote add git https://github.com/ocaml/opam-repository.git &&\
    opam pin add -n mirage-net-psock.0.1.0 https://github.com/sevenEng/mirage-net-psock.git &&\
    opam switch import bridge.export

ADD . .
RUN sudo chown opam: -R src && cd src && opam config exec -- jbuilder build bridge.exe


FROM alpine:3.6

WORKDIR /core-bridge
ADD start.sh start.sh
RUN apk update && apk add bash gmp-dev iptables iproute2
COPY --from=BUILDER /core-bridge/src/_build/default/bridge.exe bridge

EXPOSE 8080

LABEL databox.type="bridge"

CMD ["./start.sh"]
