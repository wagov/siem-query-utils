FROM mcr.microsoft.com/azure-functions/python:4-python3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true

WORKDIR /home/site/wwwroot

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt && \
    az extension add -n log-analytics -y && \
    az extension add -n resource-graph -y
RUN curl -L https://aka.ms/downloadazcopy-v10-linux -o /tmp/azcopy.tar.gz && \
    cd /tmp && tar xf azcopy.tar.gz --strip 1 && rm azcopy.tar.gz && mv -v azcopy /usr/local/bin/azcopy

COPY . ./