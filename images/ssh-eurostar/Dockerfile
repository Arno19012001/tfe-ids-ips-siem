FROM debian:12

LABEL maintainer="Arno Stärkel – TFE EPHEC 2025-2026"
LABEL description="ssh-eurostar : OpenSSH server, DMZ 10.0.10.20"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    iproute2 \
    iputils-ping \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash eurostar \
    && echo "eurostar:Eurostar2024!" | chpasswd

RUN mkdir -p /var/run/sshd \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && echo "PermitRootLogin no" >> /etc/ssh/sshd_config

# --- Wazuh Agent (installation au build, dépôt officiel) ---
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=4.14.5-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Config statique : adresse du Manager ---
RUN sed -i "s#<address>MANAGER_IP</address>#<address>10.0.30.10</address>#" /var/ossec/etc/ossec.conf

# --- Persistance de l'identité Wazuh (client.keys) au-delà d'un stop/start du nœud ---
VOLUME ["/var/ossec/etc"]

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22

CMD ["/usr/local/bin/entrypoint.sh"]
