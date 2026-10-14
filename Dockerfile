# FASE 3 - Dockerfile del agente ejecutor CyberLaws-AI (sandbox hardening)
# Base minimalista
FROM python:3.10-slim

# Sin cache de pip para reducir tamano
ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Instalar solo dependencias del ejecutor (z3 para defensa en profundidad)
RUN pip install --quiet z3-solver && \
    groupadd -r --gid 1000 cyberlaws && \
    useradd -r --uid 1000 --gid 1000 --home-dir /tmp --shell /bin/false cyberlaws && \
    mkdir -p /app /tmp && \
    chown -R 1000:1000 /app /tmp

# Copiar el ejecutor
COPY agent_executor.py /app/agent_executor.py
RUN chmod 555 /app/agent_executor.py

WORKDIR /app

# Usuario sin privilegios
USER 1000:1000

# El contenedor se ejecuta en modo lectura-unicamente (--read-only) con /tmp tmpfs.
# Entrada por defecto: espera un JSON de accion como argumento.
ENTRYPOINT ["python3", "/app/agent_executor.py"]
