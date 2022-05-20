# Prepare the base environment.
FROM mcr.microsoft.com/azure-cli:2.36.0
MAINTAINER cybersecurity@dpc.wa.gov.au
LABEL org.opencontainers.image.source https://github.com/wagov/siem-query-utils

COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
RUN curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64" && \
    chmod +x mkcert-v*-linux-amd64 && mv mkcert-v*-linux-amd64 /usr/local/bin/mkcert
RUN mkcert -install && mkcert selfsigned

EXPOSE 443

CMD ["uvicorn", "--host", "0.0.0.0", "--port", "443", "main:app", "--ssl-keyfile=./selfsigned-key.pem", "--ssl-certfile=./selfsigned.pem"]
