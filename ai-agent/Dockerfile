FROM debian:12

# --- Outils réseau + Python (cohérent avec suricata-sensor : FROM debian:12,
#     pas debian:12-slim, pour disposer des outils réseau nécessaires) ---
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    net-tools \
    curl \
    ca-certificates \
    python3 \
    python3-pip \
    zstd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# --- Installation d'Ollama (mode CPU-only confirmé empiriquement le 03/08/2026 :
#     pas de GPU dédié sur l'hôte hébergeant GNS3) ---
RUN curl -fsSL https://ollama.com/install.sh | sh

# --- Dépendances Python de l'agent IA ---
COPY requirements.txt /opt/ai-agent/requirements.txt
RUN pip install --break-system-packages --no-cache-dir -r /opt/ai-agent/requirements.txt

# --- Téléchargement du modèle Llama 3.1 8B AU BUILD, pas à l'exécution ---
# Le lab est isolé et non exposé à Internet une fois déployé (cf.
# analyse_tfe_arno_starkel_final.tex, section "Considération de sécurité — Docker").
# Seule la machine hôte dispose d'un accès Internet au moment du build.
# Empreinte mesurée empiriquement le 03/08/2026 sur l'hôte : ~4,2-4,5 Gio en RAM
# une fois chargé, ~4,9 Go sur disque (quantification Q4 par défaut d'Ollama),
# ~12s de latence CPU-only pour un prompt trivial.
RUN (ollama serve &) && \
    for i in $(seq 1 30); do \
        curl -sf http://127.0.0.1:11434/ >/dev/null 2>&1 && break; \
        sleep 1; \
    done && \
    ollama pull llama3.1:8b && \
    pkill -f "ollama serve" || true

# --- Persistance des poids du modèle au-delà d'un stop/start ou d'une recréation
#     du nœud (même logique que /var/log/suricata et /var/ossec/etc sur
#     suricata-sensor) : le contenu déjà présent dans l'image (~4,9 Go
#     pré-téléchargés ci-dessus) est copié dans le volume à la première
#     création du conteneur, puis conservé lors des recréations ultérieures
#     sans nouveau téléchargement. ---
VOLUME ["/root/.ollama"]

# --- Code de l'agent IA ---
COPY main.py /opt/ai-agent/main.py
COPY mvp/ /opt/ai-agent/mvp/
# COPY it2/ /opt/ai-agent/it2/
# ^ décommenter une fois alert_prioritization.py committé (Issue #21, étape suivante)

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

CMD ["/usr/local/bin/entrypoint.sh"]
