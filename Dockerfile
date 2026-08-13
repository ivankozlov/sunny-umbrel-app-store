FROM docker.io/metacubex/mihomo:v1.19.29@sha256:e1d7dadaa9368a52d420d65007e0e0d87cb148d292faa67326eda3fef5757f59 AS mihomo

FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ARG APP_VERSION=0.2.3
LABEL org.opencontainers.image.source="https://github.com/ivankozlov/sunny-umbrel-app-store" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="MIT AND GPL-3.0-only"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HOME=/home/sunny

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client=1:9.2p1-2+deb12u10 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 sunny \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin sunny

COPY --from=mihomo /mihomo /usr/local/bin/mihomo
RUN test -x /usr/local/bin/mihomo

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.txt

COPY LICENSE /usr/share/licenses/sunny/LICENSE
COPY LICENSES/Mihomo-GPL-3.0.txt /usr/share/licenses/mihomo/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/sunny/THIRD_PARTY_NOTICES.md
COPY src /app/src
USER 1000:1000

ENTRYPOINT ["python", "-m", "sunny_digest.main"]
