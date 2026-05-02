ARG OMNI_VERSION=16.3.0

FROM google/alloydbomni:${OMNI_VERSION}

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      postgresql-16-postgis-3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY init/ /docker-entrypoint-initdb.d/

RUN chmod +x /docker-entrypoint-initdb.d/*.sh
