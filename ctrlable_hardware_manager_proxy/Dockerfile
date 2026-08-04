ARG BUILD_FROM
FROM ${BUILD_FROM}

# python3 only -- the proxy is stdlib, matching the manager it fronts. Nothing to
# pin, nothing to audit, and no dependency that can break a released addon.
RUN apk add --no-cache python3

COPY proxy.py /app/proxy.py
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
