FROM ubuntu:24.04

# Newest version of DIE, check https://github.com/horsicq/DIE-engine/releases .
ARG DIE_VERSION=3.20
RUN apt update -qq && apt upgrade -y  && apt install -y wget && \
    wget https://github.com/horsicq/DIE-engine/releases/download/Beta/die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb && \
    apt install -y ./die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb && \
    rm die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb && rm -rf /usr/lib/die/db

# db update
COPY ./db /usr/lib/die/db

ENTRYPOINT ["/usr/bin/diec"]
