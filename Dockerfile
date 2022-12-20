FROM  --platform=linux/amd64 jupyter/datascience-notebook:python-3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

# See here for image contents: https://hub.docker.com/r/jupyter/datascience-notebook/

# User setup
USER root
RUN groupadd jovyan && usermod -g jovyan -a -G users jovyan
# Debian pkgs setup
RUN export DEBIAN_FRONTEND=noninteractive && curl -sL https://quarto.org/download/latest/quarto-linux-amd64.deb -o /tmp/quarto.deb \
 && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
 && apt-get -y --no-install-recommends install weasyprint wkhtmltopdf /tmp/quarto.deb \
 && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/quarto.deb

# Copy over python project
COPY . /app
WORKDIR /app
# Setup python path and install python project
RUN echo /opt/az/lib/python3.10/site-packages > /opt/conda/lib/python3.10/site-packages/azcli.pth \
 && conda activate && pip install -e .
# Add azure cli extensions
RUN az extension add -n log-analytics -y
# Install node components
RUN npm install -g

# Switch back to jovyan to avoid accidental container runs as root
RUN chown -R jovyan:jovyan /app
USER jovyan