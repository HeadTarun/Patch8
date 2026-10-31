FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends clang cppcheck cmake make g++ bubblewrap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /work && chown -R 10001:10001 /work
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY backend/app.py backend/auth.py backend/worker.py backend/db.py backend/scanner.py backend/taxonomy.py backend/providers.py backend/analysis_ir.py backend/ir_adapters.py backend/vulnerability_engine.py backend/analysis_pipeline.py backend/test_core.py backend/test_analysis.py backend/semgrep.yml ./
COPY data/cwe/full/cwec_v5.0.xml /app/data/cwe/full/cwec_v5.0.xml
USER 10001:10001
EXPOSE 8000
