# Argus Lite — Security Scanner
# Multi-platform image (amd64/arm64) based on Debian Bookworm Slim
# Includes all 11 Go security tools + Python argus

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="Argus Lite"
LABEL org.opencontainers.image.description="Local security scanner for authorized penetration testing"
LABEL org.opencontainers.image.source="https://github.com/cortexc0de/argus-lite"
LABEL org.opencontainers.image.licenses="MIT"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    wget \
    curl \
    unzip \
    ca-certificates \
    git \
    dnsutils \
    whois \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based security tools
# Architecture detection: amd64 or arm64
ARG TOOLS_DIR=/usr/local/bin

RUN set -ex && \
    ARCH=$(dpkg --print-architecture) && \
    # subfinder
    wget -qO /tmp/sf.zip "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_${ARCH}.zip" && \
    unzip -qo /tmp/sf.zip subfinder -d /tmp/sf && mv /tmp/sf/subfinder ${TOOLS_DIR}/subfinder && \
    chmod +x ${TOOLS_DIR}/subfinder && \
    # naabu
    wget -qO /tmp/naabu.zip "https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_linux_${ARCH}.zip" && \
    unzip -qo /tmp/naabu.zip naabu -d /tmp/naabu && mv /tmp/naabu/naabu ${TOOLS_DIR}/naabu && \
    chmod +x ${TOOLS_DIR}/naabu && \
    # nuclei
    wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${ARCH}.zip" && \
    unzip -qo /tmp/nuclei.zip nuclei -d /tmp/nuclei && mv /tmp/nuclei/nuclei ${TOOLS_DIR}/nuclei && \
    chmod +x ${TOOLS_DIR}/nuclei && \
    # httpx
    wget -qO /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_${ARCH}.zip" && \
    unzip -qo /tmp/httpx.zip httpx -d /tmp/httpx && mv /tmp/httpx/httpx ${TOOLS_DIR}/httpx && \
    chmod +x ${TOOLS_DIR}/httpx && \
    # katana
    wget -qO /tmp/katana.zip "https://github.com/projectdiscovery/katana/releases/latest/download/katana_linux_${ARCH}.zip" && \
    unzip -qo /tmp/katana.zip katana -d /tmp/katana && mv /tmp/katana/katana ${TOOLS_DIR}/katana && \
    chmod +x ${TOOLS_DIR}/katana && \
    # dnsx
    wget -qO /tmp/dnsx.zip "https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_linux_${ARCH}.zip" && \
    unzip -qo /tmp/dnsx.zip dnsx -d /tmp/dnsx && mv /tmp/dnsx/dnsx ${TOOLS_DIR}/dnsx && \
    chmod +x ${TOOLS_DIR}/dnsx && \
    # tlsx
    wget -qO /tmp/tlsx.zip "https://github.com/projectdiscovery/tlsx/releases/latest/download/tlsx_linux_${ARCH}.zip" && \
    unzip -qo /tmp/tlsx.zip tlsx -d /tmp/tlsx && mv /tmp/tlsx/tlsx ${TOOLS_DIR}/tlsx && \
    chmod +x ${TOOLS_DIR}/tlsx && \
    # ffuf
    wget -qO /tmp/ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_${ARCH}.tar.gz" && \
    tar xzf /tmp/ffuf.tar.gz -C ${TOOLS_DIR} ffuf && \
    chmod +x ${TOOLS_DIR}/ffuf && \
    # gau (getallurls)
    wget -qO /tmp/gau.tar.gz "https://github.com/lc/gau/releases/latest/download/gau_linux_${ARCH}.tar.gz" && \
    tar xzf /tmp/gau.tar.gz -C ${TOOLS_DIR} gau && \
    chmod +x ${TOOLS_DIR}/gau && \
    # gowitness
    wget -qO ${TOOLS_DIR}/gowitness "https://github.com/sensepost/gowitness/releases/latest/download/gowitness-linux-${ARCH}" && \
    chmod +x ${TOOLS_DIR}/gowitness && \
    # whatweb (Ruby-based, available in apt)
    apt-get update && apt-get install -y --no-install-recommends whatweb && rm -rf /var/lib/apt/lists/* && \
    # Cleanup
    rm -rf /tmp/*.zip /tmp/*.tar.gz /tmp/sf /tmp/naabu /tmp/nuclei /tmp/httpx \
           /tmp/katana /tmp/dnsx /tmp/tlsx /tmp/ffuf /tmp/gau

# Install argus-lite
WORKDIR /app
COPY . .
RUN pip3 install --no-cache-dir --break-system-packages -e .

# Initialize config
ENV ARGUS_HOME=/root/.argus-lite
RUN argus init || true

# Reports volume — mount here to persist reports
RUN mkdir -p /reports
VOLUME /reports

ENTRYPOINT ["argus"]
CMD ["--help"]
