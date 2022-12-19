FROM  --platform=linux/amd64 jupyter/datascience-notebook:python-3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

# See here for image contents: https://hub.docker.com/r/jupyter/datascience-notebook/

# We want to run common-debian.sh from here:
# https://github.com/microsoft/vscode-dev-containers/tree/main/script-library#development-container-scripts
# But that script assumes that the main non-root user (in this case jovyan)
# is in a group with the same name (in this case jovyan).  So we must first make that so.
RUN curl -sL https://raw.githubusercontent.com/microsoft/vscode-dev-containers/main/script-library/common-debian.sh -o /tmp/common-debian.sh
USER root
RUN apt-get update \
 && groupadd jovyan \
 && usermod -g jovyan -a -G users jovyan \
 && bash /tmp/common-debian.sh \
 && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/common-debian.sh

USER jovyan

COPY . /app
WORKDIR /app
#RUN ["/bin/bash", "-i", "install.sh"]

ENTRYPOINT [ "/bin/bash", "-i" ]
CMD [ "-c", "siem_query_utils serve" ]

