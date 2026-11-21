# syntax=docker/dockerfile:1.7
# Образ ноды CORE. Сборка: docker build -t core-node .  (из каталога CORE/)

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p core-node -p core-cli \
    && mkdir -p /out \
    && cp target/release/core-node target/release/core-cli /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin core \
    && mkdir -p /data && chown core /data
COPY --from=build /out/core-node /out/core-cli /usr/local/bin/
COPY docker/healthcheck.sh /usr/local/bin/core-healthcheck
USER core
ENV CORE_DATA_DIR=/data \
    CORE_LISTEN=0.0.0.0:7443 \
    RUST_LOG=info
VOLUME ["/data"]
EXPOSE 7443
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 CMD ["core-healthcheck"]
ENTRYPOINT ["core-node"]
CMD ["run"]
