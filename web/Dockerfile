# 多阶段构建：编译阶段
FROM rust:1.75-slim as builder

WORKDIR /app

# 安装编译依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY ../Cargo.toml ../Cargo.lock ./
COPY ../src ./src
COPY ../build.rs ./build.rs
COPY web/Cargo.toml ./web/
COPY web/src ./web/src
COPY web/static ./web/static

# 构建 Web 应用
WORKDIR /app/web
RUN cargo build --release

# 运行阶段
FROM debian:bookworm-slim

WORKDIR /app

# 安装运行依赖（剥离编译工具链）
RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制编译产物
COPY --from=builder /app/web/target/release/teehee-web /usr/local/bin/

# 复制静态文件
COPY --from=builder /app/web/static /app/static

# 创建必要的目录
RUN mkdir -p /app/workspaces /app/downloads /app/data \
    && adduser --system --uid 10001 --group teehee \
    && chown -R teehee:teehee /app

# 以非 root 用户运行
USER 10001:10001

# 设置环境变量
ENV DATABASE_URL=sqlite:/app/data/teehee.db
ENV RUST_LOG=teehee_web=info

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/stats || exit 1

# 启动应用
CMD ["teehee-web"]

