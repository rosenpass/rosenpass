FROM rust:slim as build

RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  libclang-dev \
  libcap2-bin \
  git \
  inotify-tools

RUN adduser --system --uid 768 --group rosenpass --home /var/lib/rosenpass

USER rosenpass:rosenpass
RUN cd ~rosenpass \
  && git clone --depth 1 "https://github.com/rosenpass/rosenpass" -b dev/broker-architecture rosenpass-source \
  && cd rosenpass-source \
  && mkdir -p ~rosenpass/usr \
  && cargo install --path rosenpass --root ~rosenpass/usr --bins \
  && cargo install --path wireguard-broker --root ~rosenpass/usr --bins \
  && cd ~rosenpass \
  && rm -R rosenpass-source
USER root:root

# TODO: Is this proper handling of ambient capabilities?
RUN setcap CAP_NET_ADMIN=+ep ~rosenpass/usr/bin/rosenpass-wireguard-broker-privileged

VOLUME /config
COPY ./entrypoint.sh /usr/local/sbin/docker_entrypoint
COPY ./fd_passing.pl /usr/local/sbin/fd_passing
RUN chmod a+x /usr/local/sbin/docker_entrypoint /usr/local/sbin/fd_passing
ENTRYPOINT ["/usr/local/sbin/docker_entrypoint"]

VOLUME /socket

CMD rosenpass config.toml
