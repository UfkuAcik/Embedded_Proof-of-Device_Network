# syntax=docker/dockerfile:1.7
FROM rust:1.85.0-bookworm@sha256:0ff31c9ffa641a62e48d543fb00b4960955ea375f40776f40f585b89e654cc5e AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY protocol ./protocol
COPY node ./node
RUN cargo build --locked --release -p epdn-node

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN mkdir -p /var/lib/epdn \
    && chown 65532:65532 /var/lib/epdn
COPY --from=builder /src/target/release/epdn-node /usr/local/bin/epdn-node

ENV EPDN_BIND_ADDR=0.0.0.0:8745 \
    EPDN_STATE_PATH=/var/lib/epdn/node-state.journal \
    RUST_LOG=epdn_node=info

USER 65532:65532
VOLUME ["/var/lib/epdn"]
EXPOSE 8745
ENTRYPOINT ["/usr/local/bin/epdn-node"]
