FROM rust:1.75-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ../Cargo.toml ../Cargo.lock ./
COPY ../src ./src
COPY ../build.rs ./build.rs
COPY web/Cargo.toml ./web/
COPY web/src ./web/src
COPY web/static ./web/static

WORKDIR /app/web
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/web/target/release/teehee-web /usr/local/bin/

COPY --from=builder /app/web/static /app/static

RUN mkdir -p /app/workspaces /app/downloads /app/data \
    && adduser --system --uid 10001 --group teehee \
    && chown -R teehee:teehee /app

USER 10001:10001

ENV DATABASE_URL=sqlite:/app/data/teehee.db
ENV RUST_LOG=teehee_web=info

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/stats || exit 1

CMD ["teehee-web"]

