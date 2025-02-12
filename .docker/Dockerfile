# syntax=docker/dockerfile:1

ARG BASE_IMAGE=debian:bookworm-slim

# Stage 1: Base image with cargo-chef installed
FROM rust:latest AS chef
RUN cargo install cargo-chef
# install software required for liboqs-rust
RUN apt-get update && apt-get install -y clang cmake && rm -rf /var/lib/apt/lists/*

# Stage 2: Prepare the cargo-chef recipe
FROM chef AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Cache dependencies using the recipe
FROM chef AS cacher
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 4: Build the application
FROM cacher AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 5: Annotate the base image with OCI Image Annotations, also install runtime-dependencies
FROM ${BASE_IMAGE} AS annotated_base_image

RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*

ARG VERSION
ARG REF_NAME
ARG BUILD_DATE
ARG VCS_REF
ARG AUTHORS="Karolin Varner <karo@cupdev.net>, wucke13 <wucke13@gmail.com>"
ARG URL="https://rosenpass.eu/"
ARG DOCUMENTATION="https://rosenpass.eu/docs/"
ARG SOURCE="https://github.com/rosenpass/rosenpass"
ARG VENDOR="Rosenpass e.V."
ARG LICENSES="MIT OR Apache-2.0"
ARG TITLE="Rosenpass"
ARG DESCRIPTION
ARG BASE_DIGEST
ARG BASE_IMAGE
LABEL org.opencontainers.image.created=${BUILD_DATE} \
      org.opencontainers.image.authors=${AUTHORS} \
      org.opencontainers.image.url=${URL} \
      org.opencontainers.image.documentation=${DOCUMENTATION} \
      org.opencontainers.image.source=${SOURCE} \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.revision=${VCS_REF} \
      org.opencontainers.image.vendor=${VENDOR} \
      org.opencontainers.image.licenses=${LICENSES} \
      org.opencontainers.image.ref.name=${REF_NAME} \
      org.opencontainers.image.title=${TITLE} \
      org.opencontainers.image.description=${DESCRIPTION} \
      org.opencontainers.image.base.digest=${BASE_DIGEST} \
      org.opencontainers.image.base.name=${BASE_IMAGE}


# Final Stage (rosenpass): Copy the rosenpass binary
FROM annotated_base_image AS rosenpass
COPY --from=builder /app/target/release/rosenpass /usr/local/bin/rosenpass
ENTRYPOINT [ "/usr/local/bin/rosenpass" ]

# Final Stage (rp): Copy the rp binary
FROM annotated_base_image AS rp

RUN apt-get update && apt-get install -y wireguard && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rp /usr/local/bin/rp
ENTRYPOINT [ "/usr/local/bin/rp" ]
