FROM jupyter/datascience-notebook:python-3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

# See here for image contents: https://hub.docker.com/r/jupyter/datascience-notebook/

# User setup and group fix
USER root
RUN groupmod -n jovyan users

# Debian pkgs setup
RUN apt-get -y update && apt-get -y --no-install-recommends install weasyprint wkhtmltopdf byobu\
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Copy over python project
COPY . /app
WORKDIR /app
RUN /app/scripts/install-quarto.sh
RUN chown -R jovyan:jovyan /app

USER jovyan
SHELL ["/bin/bash", "-l", "-c"]
# Install poetry
RUN pip install poetry
# Freshen npm
RUN npm install -g npm

# Sleep forever on launch to keep container running
ENTRYPOINT ["/bin/bash", "-l", "-c", "sleep infinity"]