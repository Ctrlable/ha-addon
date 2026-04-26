ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache \
    wireguard-tools \
    curl \
    bash \
    iproute2 \
    iptables \
    ip6tables \
    python3 \
    ca-certificates

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
