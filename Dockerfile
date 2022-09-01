# Prepare the base environment.
FROM python:3
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN az extension add -n log-analytics -y
RUN az extension add -n resource-graph -y
RUN curl -L https://aka.ms/downloadazcopy-v10-linux -o /tmp/azcopy.tar.gz
RUN cd /tmp && tar xf azcopy.tar.gz --strip 1 && rm azcopy.tar.gz && mv -v azcopy /usr/local/bin/azcopy

COPY . ./

EXPOSE 8000

CMD ["bash", "-c", "gunicorn -k uvicorn.workers.UvicornH11Worker main:app"]
