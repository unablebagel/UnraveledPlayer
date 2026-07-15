# UnraveledPlayer — standalone Docker app (deployed via render.yaml).
# The whole app is stdlib-only Python (no requirements.txt on purpose).
# The server reads $PORT at runtime, so the platform's injected value wins.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=7860

WORKDIR /space
COPY pipeline/ pipeline/

EXPOSE 7860
CMD ["python", "-m", "pipeline.scenario_builder.serve"]
