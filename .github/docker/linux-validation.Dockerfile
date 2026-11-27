FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 65532 runner \
 && useradd --uid 65532 --gid 65532 --create-home --shell /usr/sbin/nologin runner
COPY execute-linux-inner.sh /usr/local/bin/execute-linux-inner.sh
RUN chmod 0555 /usr/local/bin/execute-linux-inner.sh
USER 65532:65532
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/execute-linux-inner.sh"]
