# Prepare the base environment.
FROM mcr.microsoft.com/azure-cli:2.36.0
MAINTAINER cybersecurity@dpc.wa.gov.au
LABEL org.opencontainers.image.source https://github.com/wagov/siem-query-utils

COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "--host", "0.0.0.0", "main:app"]
