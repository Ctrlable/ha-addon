ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM ${BUILD_FROM}

LABEL \
  io.hass.name="Ctrlable Shower Server" \
  io.hass.description="Keeps U by Moen showers controllable when Moen's cloud runs out of daily messages" \
  io.hass.type="addon" \
  io.hass.version="1.0.0" \
  io.hass.arch="aarch64|amd64|armhf|armv7|i386" \
  maintainer="Ctrlable <info@ctrlable.com>"

# server.py is stdlib only; openssl makes the certificate on first start.
RUN apk add --no-cache python3 openssl

COPY server.py /app/server.py
COPY run.sh    /run.sh
RUN chmod a+x /run.sh

CMD ["/run.sh"]
