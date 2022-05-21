# Prepare the base environment.
FROM mcr.microsoft.com/azure-cli:2.36.0
MAINTAINER cybersecurity@dpc.wa.gov.au
LABEL org.opencontainers.image.source https://github.com/wagov/siem-query-utils

WORKDIR /app
RUN az extension add -n log-analytics -y
RUN openssl req -x509 -nodes -newkey rsa:4096 -keyout selfsigned-key.pem -out selfsigned.pem -sha256 -days 3650 -subj '/CN=localhost'
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . ./

EXPOSE 443

CMD ["uvicorn", "--host", "0.0.0.0", "--port", "443", "main:app", "--ssl-keyfile=./selfsigned-key.pem", "--ssl-certfile=./selfsigned.pem"]
