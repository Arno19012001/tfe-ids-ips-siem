FROM debian:12

LABEL maintainer="Arno Stärkel – TFE EPHEC 2025-2026"
LABEL description="web-eurostar : Apache2 + MariaDB, DMZ 10.0.10.10"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apache2 \
    mariadb-server \
    php \
    libapache2-mod-php \
    php-mysql \
    iproute2 \
    iputils-ping \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

COPY index.html /var/www/html/index.html
COPY index.php /var/www/html/index.php

# --- Wazuh Agent (installation au build, dépôt officiel) ---
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=4.14.5-1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Config statique : adresse du Manager + collecte logs Apache (Scénario C, Issue #20) ---
RUN sed -i "s#<address>MANAGER_IP</address>#<address>10.0.30.10</address>#" /var/ossec/etc/ossec.conf \
    && LASTLINE=$(grep -n "</ossec_config>" /var/ossec/etc/ossec.conf | tail -1 | cut -d: -f1) \
    && sed -i "${LASTLINE}s#</ossec_config>#  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/apache2/access.log</location>\n  </localfile>\n  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/apache2/error.log</location>\n  </localfile>\n</ossec_config>#" /var/ossec/etc/ossec.conf

# --- Persistance de l'identité Wazuh (client.keys) au-delà d'un stop/start du nœud ---
VOLUME ["/var/ossec/etc"]

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 3306

CMD ["/usr/local/bin/entrypoint.sh"]
