# syntax=docker/dockerfile:1
FROM ubuntu:noble

RUN yes | unminimize
RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates locales curl vim \
    && rm -Rf /var/lib/apt/lists/* \
    && locale-gen "en_US.UTF-8"

USER ubuntu:ubuntu
WORKDIR /app
ENV LANG="en_US.UTF-8"

ADD --chown=ubuntu:ubuntu https://astral.sh/uv/install.sh uv-installer.sh
RUN sh uv-installer.sh && rm uv-installer.sh
ENV PATH="/home/ubuntu/.local/bin/:$PATH"

RUN uv tool install --no-cache rtty-soda
