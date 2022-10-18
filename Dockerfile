FROM python:3
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

EXPOSE 8000


RUN pip install poetry
RUN curl -L https://aka.ms/downloadazcopy-v10-linux -o /tmp/azcopy.tar.gz && \
    cd /tmp && tar xf azcopy.tar.gz --strip 1 && rm azcopy.tar.gz && mv -v azcopy /usr/local/bin/azcopy
COPY . ./
RUN poetry install
RUN poetry run az extension add -n log-analytics -y
RUN poetry run az extension add -n resource-graph -y


ENTRYPOINT [ "poetry", "run", "siem_query_utils", "serve" ]