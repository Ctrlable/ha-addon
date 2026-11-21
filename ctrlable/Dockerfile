ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache \
    wireguard-tools \
    curl \
    bash \
    iproute2 \
    nftables \
    iptables \
    ip6tables \
    python3 \
    py3-websockets \
    ca-certificates

COPY store/ /opt/ctrlable/store/
COPY shell_bridge.py /opt/ctrlable/shell_bridge.py
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
