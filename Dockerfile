FROM python:3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

EXPOSE 8000


ENV POETRY_HOME=/opt/poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
RUN ln -s $POETRY_HOME/bin/poetry /usr/local/bin/poetry
COPY . ./
RUN poetry install
RUN poetry run az extension add -n log-analytics -y


ENTRYPOINT [ "poetry", "run", "siem_query_utils", "serve" ]