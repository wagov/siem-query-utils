FROM  --platform=linux/amd64 jupyter/datascience-notebook:python-3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

# See here for image contents: https://hub.docker.com/r/jupyter/datascience-notebook/

# User setup
USER root
RUN groupadd jovyan && usermod -g jovyan -a -G users jovyan
# Debian pkgs setup
RUN curl -sL https://quarto.org/download/latest/quarto-linux-amd64.deb -o /tmp/quarto.deb \
 && apt-get -y update && apt-get -y --no-install-recommends install weasyprint wkhtmltopdf /tmp/quarto.deb \
 && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/quarto.deb

# Copy over python project
USER jovyan
COPY . /app
WORKDIR /app
SHELL ["/bin/bash", "-l", "-c"]
# Install python project, azure cli extensions and npm subproject
RUN pip install poetry && poetry install && az extension add -n log-analytics -y
RUN npm install
