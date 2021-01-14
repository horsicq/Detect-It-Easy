FROM debian:bullseye-slim

RUN apt update -qq && apt upgrade -y && apt install -y wget tar libglib2.0-0 && \
    wget https://github.com/horsicq/DIE-engine/releases/download/3.01/die_lin64_portable_3.01.tar.gz && \
    tar -xzf die_lin64_portable_3.01.tar.gz

# db update
RUN rm -rf /die_lin64_portable/base/db
COPY ./db /die_lin64_portable/base/db

ENTRYPOINT ["/die_lin64_portable/diec.sh"]
