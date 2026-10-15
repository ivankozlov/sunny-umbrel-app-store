FROM docker.io/metacubex/mihomo:v1.19.29@sha256:e1d7dadaa9368a52d420d65007e0e0d87cb148d292faa67326eda3fef5757f59 AS mihomo

FROM python:3.14.7-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56

ARG APP_VERSION=0.3.0
LABEL org.opencontainers.image.source="https://github.com/ivankozlov/sunny-umbrel-app-store" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.licenses="MIT AND GPL-3.0-only"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HOME=/tmp

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client=1:9.2p1-2+deb12u10 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 guardian \
    && groupadd --gid 1001 collector \
    && groupadd --gid 1002 web \
    && useradd --uid 1000 --gid 1000 --create-home --shell /usr/sbin/nologin guardian \
    && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin collector \
    && useradd --uid 1002 --gid 1002 --create-home --shell /usr/sbin/nologin web

COPY --from=mihomo /mihomo /usr/local/bin/mihomo
RUN test -x /usr/local/bin/mihomo

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r /app/requirements.txt

COPY LICENSE /usr/share/licenses/sunny/LICENSE
COPY LICENSES/Mihomo-GPL-3.0.txt /usr/share/licenses/mihomo/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/sunny/THIRD_PARTY_NOTICES.md
COPY src /app/src
USER 1001:1001

ENTRYPOINT ["python", "-m", "sunny_digest.main"]
