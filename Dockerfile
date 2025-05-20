FROM ubuntu:24.04

RUN apt update -qq && apt upgrade -y  && apt install -y wget && \
    # Beta version needed to support recent signatures
    wget https://github.com/horsicq/DIE-engine/releases/download/Beta/die_3.10_Ubuntu_24.04_amd64.deb  && \
    apt install -y ./die_3.10_Ubuntu_24.04_amd64.deb && \
    rm die_3.10_Ubuntu_24.04_amd64.deb && rm -rf /usr/lib/die/db

# db update
COPY ./db /usr/lib/die/db

ENTRYPOINT ["/usr/bin/diec"]
