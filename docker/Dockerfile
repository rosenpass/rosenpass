# syntax=docker/dockerfile:1

ARG BASE_IMAGE=debian:bookworm-slim
ARG CHEF_IMAGE=rust:slim-bookworm

# Stage 1: Base image with cargo-chef installed
FROM ${CHEF_IMAGE} AS chef
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

# Stage 5: Install runtime-dependencies in the base image
FROM ${BASE_IMAGE} AS base_image_with_dependencies

RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*

# Final Stage (rosenpass): Copy the rosenpass binary
FROM base_image_with_dependencies AS rosenpass
COPY --from=builder /app/target/release/rosenpass /usr/local/bin/rosenpass
ENTRYPOINT [ "/usr/local/bin/rosenpass" ]

# Final Stage (rp): Copy the rp binary
FROM base_image_with_dependencies AS rp

RUN apt-get update && apt-get install -y wireguard && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rp /usr/local/bin/rp
ENTRYPOINT [ "/usr/local/bin/rp" ]
