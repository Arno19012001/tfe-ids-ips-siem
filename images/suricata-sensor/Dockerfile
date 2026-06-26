FROM debian:12

# Activation de bookworm-backports pour Suricata
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" \
    >> /etc/apt/sources.list

# Outils réseau (bridge, diagnostic) — depuis bookworm/main
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    net-tools \
    bridge-utils \
    ebtables \
    iptables \
    tcpdump \
    && apt-get install -y -t bookworm-backports \
    suricata \
    libnetfilter-queue1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY suricata.yaml /etc/suricata/suricata.yaml
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
