##
## App Relacionamento Cliente — Dockerfile (produção simples)
##

# 1) Base Python minimalista (mantemos 3.9 para compatibilidade do projeto)
FROM python:3.9-slim-bookworm

# 2) Configurações de ambiente básicas e caminhos
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    # Persistência do SQLite (pode ser montado como volume)
    SQLITE_DB_PATH=/app/data/relacionamento_cliente.db \
    # Força modo THIN do oracledb por padrão (sem cliente OCI)
    ORACLE_THICK_LIB_DIR=""

# 3) Diretório de trabalho e usuário não-root
WORKDIR /app
RUN useradd -m -r -s /bin/false app && mkdir -p /app/data

# 4) Dependências de sistema (libaio para uso eventual do modo THICK)
RUN apt-get update \
 && apt-get install -y --no-install-recommends libaio1 curl \
 && rm -rf /var/lib/apt/lists/*

# 5) Instala dependências Python primeiro (melhor cache)
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir gunicorn

# 6) Copia o restante do código
COPY . .
RUN chown -R app:app /app

# 7) Troca para usuário não-root
USER app

# 8) Porta da aplicação
EXPOSE 5000

# 9) Healthcheck simples (usa endpoint /healthz)
# Nota: evitamos heredoc aqui porque alguns linters não entendem; usamos curl diretamente.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:5000/healthz >/dev/null || exit 1

# 10) Processo de produção com Gunicorn
# Obs: variável PORT pode ser passada em runtime, padrão 5000
CMD ["gunicorn", "-w", "2", "-k", "gthread", "-t", "60", "-b", "0.0.0.0:${PORT:-5000}", "app:app"]
