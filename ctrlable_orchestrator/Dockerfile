ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM ${BUILD_FROM}

LABEL \
  io.hass.name="Ctrlable Orchestrator" \
  io.hass.description="Open the Ctrlable Orchestrator from inside Ctrlable Pro" \
  io.hass.type="addon" \
  io.hass.version="1.0.0" \
  io.hass.arch="aarch64|amd64|armhf|armv7|i386" \
  maintainer="Ctrlable <info@ctrlable.com>"

# python3 only — proxy.py is stdlib, so the image is a base image plus python3
# and builds on every arch with no wheels or compiler.
RUN apk add --no-cache python3

COPY proxy.py /app/proxy.py
COPY run.sh   /run.sh
RUN chmod a+x /run.sh

EXPOSE 8099
CMD ["/run.sh"]
