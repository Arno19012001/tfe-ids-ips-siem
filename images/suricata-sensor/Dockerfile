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

# --- Wazuh Agent (installation au build, dépôt officiel) ---
RUN apt-get update && apt-get install -y curl gnupg \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=4.14.5-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Config statique : adresse du Manager + collecte EVE JSON ---
RUN sed -i "s#<address>MANAGER_IP</address>#<address>10.0.30.10</address>#" /var/ossec/etc/ossec.conf \
    && sed -i "s#</ossec_config>#  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/suricata/eve.json</location>\n  </localfile>\n</ossec_config>#" /var/ossec/etc/ossec.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY suricata.yaml /etc/suricata/suricata.yaml
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
