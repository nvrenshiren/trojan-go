# Trojan-Go 多阶段构建
# 第一阶段：编译
FROM golang:alpine AS builder

# 安装编译依赖
RUN apk add --no-cache git make

# 设置工作目录
WORKDIR /build

# 获取源码（支持两种方式）
# 方式1: 从源码构建（通过 docker build --build-arg BUILD_FROM_SOURCE=1）
ARG BUILD_FROM_SOURCE=0
ARG REF=main

# 如果需要从源码构建，复制本地文件；否则克隆仓库
RUN if [[ "${BUILD_FROM_SOURCE}" == "1" ]]; then \
        echo "从构建上下文复制源码"; \
    else \
        echo "从 GitHub 克隆源码"; \
        git clone https://github.com/nvrenshiren/trojan-go.git . && \
        if [[ "${REF}" != "main" ]]; then \
            git checkout ${REF}; \
        fi \
    fi

# 获取版本信息
ARG VERSION=unknown
ARG COMMIT=unknown
ENV VERSION=${VERSION} COMMIT=${COMMIT}

# 编译前下载 geoip 数据
RUN wget -q https://github.com/v2fly/geoip/raw/release/geoip.dat -O geoip.dat && \
    wget -q https://github.com/v2fly/geoip/raw/release/geoip-only-cn-private.dat -O geoip-only-cn-private.dat && \
    wget -q https://github.com/v2fly/domain-list-community/raw/release/dlc.dat -O geosite.dat

# 编译
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -tags "full" \
    -trimpath \
    -ldflags="-s -w -X github.com/p4gefau1t/trojan-go/constant.Version=${VERSION} -X github.com/p4gefau1t/trojan-go/constant.Commit=${COMMIT}" \
    -o trojan-go .

# 第二阶段：运行
FROM alpine

# 安装运行时依赖
RUN apk add --no-cache tzdata ca-certificates

# 设置工作目录
WORKDIR /app

# 从编译阶段复制可执行文件和依赖数据
COPY --from=builder /build/trojan-go /app/
COPY --from=builder /build/*.dat /app/

# 创建数据目录（用于存储 geoip/geosite 数据）
RUN mkdir -p /app/data

# 创建非 root 用户
RUN adduser -D -u 1000 trojan

# 切换到非 root 用户
USER trojan

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:443 || exit 1

# 默认端口
EXPOSE 443 80

# 默认配置（用户应挂载自己的配置）
COPY --chown=trojan:trojan example/server.json /app/config.json

ENTRYPOINT ["/app/trojan-go"]
CMD ["-config", "/app/config.json"]
