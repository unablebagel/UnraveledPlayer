# UnraveledPlayer — standalone Docker app (deployed via render.yaml).
# The whole app is stdlib-only Python (no requirements.txt on purpose).
# The server reads $PORT at runtime, so the platform's injected value wins.
FROM python:3.12-slim

# Graphviz `dot` renders the /evolution session-evolution SVG (system
# binary, not a Python dep — the endpoint degrades to DOT source without it).
RUN apt-get update \
    && apt-get install -y --no-install-recommends graphviz \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PORT=7860

WORKDIR /space
COPY pipeline/ pipeline/

EXPOSE 7860
CMD ["python", "-m", "pipeline.scenario_builder.serve"]
