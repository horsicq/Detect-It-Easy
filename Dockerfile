FROM ubuntu:focal

RUN apt update -qq && apt upgrade -y && apt install -y wget tar libglib2.0-0
RUN apt install -y libpcre2-posix2 libpcre2-dev
RUN apt install -y libdouble-conversion3
RUN wget https://github.com/horsicq/DIE-engine/releases/download/3.10/die_3.10_portable_Ubuntu_20.04_amd64.tar.gz && \
    tar -xzf die_3.10_portable_Ubuntu_20.04_amd64.tar.gz

# db update
RUN rm -rf /die_linu_portable/base/db
COPY ./db /die_lin64_portable/base/db

ENTRYPOINT ["/die_linux_portable/diec.sh"]
