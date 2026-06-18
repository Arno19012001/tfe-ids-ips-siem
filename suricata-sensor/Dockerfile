FROM debian:12
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    net-tools \
    bridge-utils \
    ebtables \
    iptables \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
CMD ["/usr/local/bin/entrypoint.sh"]
