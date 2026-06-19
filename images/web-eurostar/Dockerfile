FROM debian:12

LABEL maintainer="Arno Stärkel – TFE EPHEC 2025-2026"
LABEL description="web-eurostar : Apache2 + MariaDB, DMZ 10.0.10.10"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apache2 \
    mariadb-server \
    iproute2 \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY index.html /var/www/html/index.html

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80 3306

CMD ["/usr/local/bin/entrypoint.sh"]
