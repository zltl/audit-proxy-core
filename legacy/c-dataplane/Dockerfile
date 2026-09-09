# Legacy C data plane image (deprecated).
# Build from repo root:
#   docker build -f legacy/c-dataplane/Dockerfile -t audit-proxy-core:legacy .
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libssh-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY legacy/c-dataplane/ ./
RUN make clean && make release

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libssh-4 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin audit-proxy \
    && mkdir -p /etc/audit-proxy /var/log/audit-proxy/audit \
    && chown audit-proxy:audit-proxy /etc/audit-proxy /var/log/audit-proxy /var/log/audit-proxy/audit

COPY --from=builder /build/build/bin/audit-proxy-core /usr/local/bin/audit-proxy-core
COPY docs/config.example.ini /etc/audit-proxy/config.example.ini

RUN ssh-keygen -t ed25519 -f /etc/audit-proxy/host_key -N "" \
    && chown audit-proxy:audit-proxy /etc/audit-proxy/host_key*

USER ssh-proxy

EXPOSE 2222 9090

ENTRYPOINT ["audit-proxy-core"]
CMD ["-c", "/etc/audit-proxy/config.ini"]
