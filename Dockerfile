# syntax=docker/dockerfile:1
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

RUN useradd --system --uid 10001 foolsgold \
    && mkdir -p /var/lib/fools-gold \
    && chown foolsgold /var/lib/fools-gold

USER foolsgold
WORKDIR /var/lib/fools-gold
# This image runs finite CLI jobs by default, not a persistent service.
# A deployment overriding CMD to serve should supply its own health probe.
HEALTHCHECK NONE
ENTRYPOINT ["fools-gold"]
CMD ["--help"]
