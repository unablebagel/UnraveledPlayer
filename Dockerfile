# scenario_builder_space — Hugging Face Docker Space.
# The whole app is stdlib-only Python (no requirements.txt on purpose).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=7860

WORKDIR /space
COPY pipeline/ pipeline/

EXPOSE 7860
CMD ["python", "-m", "pipeline.scenario_builder.serve"]
