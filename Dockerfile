FROM mcr.microsoft.com/devcontainers/python:3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

EXPOSE 8000

COPY . /app
WORKDIR /app
RUN ["/bin/bash", "-i", "install.sh"]

ENTRYPOINT [ "/bin/bash", "-i" ]
CMD [ "-c", "poetry run siem_query_utils serve" ]