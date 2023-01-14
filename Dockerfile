FROM  --platform=linux/amd64 jupyter/datascience-notebook:python-3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

# See here for image contents: https://hub.docker.com/r/jupyter/datascience-notebook/

# User setup and group fix
USER root
RUN groupmod -n jovyan users
RUN apt-get update && apt-get install -y --no-install-recommends dialog openssh-server \
    && echo "root:Docker!" | chpasswd
COPY sshd_config /etc/ssh/

# Debian pkgs setup
RUN curl -sL https://quarto.org/download/latest/quarto-linux-amd64.deb -o /tmp/quarto.deb \
 && apt-get -y update && apt-get -y --no-install-recommends install weasyprint wkhtmltopdf byobu /tmp/quarto.deb \
 && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/quarto.deb

# Copy over python project
COPY . /app
WORKDIR /app
RUN chown -R jovyan:jovyan /app

USER jovyan
SHELL ["/bin/bash", "-l", "-c"]
# Install poetry
RUN pip install poetry