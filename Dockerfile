FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libssh-dev \
    pkg-config \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN make clean && make release

# --- Runtime stage ---
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libssh-4 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin ssh-proxy \
    && mkdir -p /etc/ssh-proxy /var/log/ssh-proxy/audit \
    && chown ssh-proxy:ssh-proxy /etc/ssh-proxy /var/log/ssh-proxy /var/log/ssh-proxy/audit

COPY --from=builder /build/build/bin/ssh-proxy-core /usr/local/bin/ssh-proxy-core
COPY --from=builder /build/docs/config.example.ini /etc/ssh-proxy/config.example.ini

RUN ssh-keygen -t ed25519 -f /etc/ssh-proxy/host_key -N "" \
    && chown ssh-proxy:ssh-proxy /etc/ssh-proxy/host_key*

USER ssh-proxy

EXPOSE 2222 9090

ENTRYPOINT ["ssh-proxy-core"]
CMD ["-c", "/etc/ssh-proxy/config.ini"]
