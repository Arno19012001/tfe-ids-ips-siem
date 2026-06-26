FROM debian:12

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    net-tools \
    bridge-utils \
    ebtables \
    iptables \
    tcpdump \
    suricata \
    libnetfilter-queue1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY suricata.yaml /etc/suricata/suricata.yaml
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
