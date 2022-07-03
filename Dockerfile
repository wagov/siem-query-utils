# Prepare the base environment.
FROM mcr.microsoft.com/azure-cli:2.37.0
MAINTAINER cybersecurity@dpc.wa.gov.au
LABEL org.opencontainers.image.source https://github.com/wagov/siem-query-utils

ENV API_TOKEN changeme
ENV FQDN localhost

WORKDIR /app
RUN az extension add -n log-analytics -y
RUN az extension add -n resource-graph -y
RUN curl -L https://aka.ms/downloadazcopy-v10-linux -o /tmp/azcopy.tar.gz
RUN cd /tmp && tar xf azcopy.tar.gz --strip 1 && rm azcopy.tar.gz && mv -v azcopy /usr/local/bin/azcopy
RUN curl -L https://github.com/caddyserver/caddy/releases/download/v2.5.1/caddy_2.5.1_linux_amd64.tar.gz -o /tmp/caddy.tar.gz
RUN cd /tmp && tar xf caddy.tar.gz && rm caddy.tar.gz && mv -v caddy /usr/local/bin/caddy
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . ./

EXPOSE 80 443

CMD ["bash", "-c", "uvicorn main:app & caddy reverse-proxy --from ${FQDN} --to 127.0.0.1:8000"]
