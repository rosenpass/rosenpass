FROM rust:slim as build

RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  pkg-config \
  libclang-dev \
  libsodium-dev

WORKDIR /code
COPY . /code

RUN cargo install --path rosenpass --root / --bins \
  && cargo install --path wireguard-broker --root / --bins
# RUN apt-get install -y libcap2-bin \
#   setcap CAP_NET_ADMIN=+eip "$(which rosenpass-wireguard-broker-privileged)"

CMD rosenpass
