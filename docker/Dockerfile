# syntax=docker/dockerfile:1
FROM ubuntu:resolute

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends build-essential ca-certificates locales curl vim keepassxc-minimal \
    && rm -Rf /var/lib/apt/lists/* \
    && locale-gen "en_US.UTF-8"

USER ubuntu:ubuntu
WORKDIR /app
ENV LANG="en_US.UTF-8"
ENV HOME="/home/ubuntu"
ENV PYTHON_GIL=0

ADD --chown=ubuntu:ubuntu vimrc $HOME/.vim/vimrc
ADD --chown=ubuntu:ubuntu museum.env $HOME/.soda/museum.env
ADD --chown=ubuntu:ubuntu unset.sh $HOME/.soda/unset.sh

ADD --chown=ubuntu:ubuntu https://astral.sh/uv/install.sh uv-installer.sh
RUN sh uv-installer.sh && rm uv-installer.sh
ENV PATH="/home/ubuntu/.local/bin/:$PATH"

RUN uv tool install --python 3.15t --no-cache "rtty-soda[cli]"
RUN echo "set -a" >> $HOME/.bashrc