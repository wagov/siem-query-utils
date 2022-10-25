FROM python:3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

EXPOSE 8000

SHELL ["/bin/bash", "--login", "-c"]
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash
RUN nvm install node
ENV POETRY_HOME=/opt/poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
RUN ln -s $POETRY_HOME/bin/poetry /usr/local/bin/poetry
COPY . ./
RUN poetry install
RUN poetry run az extension add -n log-analytics -y
RUN cd atlaskit-transformer && npm ci && npm cache clean --force

ENTRYPOINT [ "poetry", "run", "siem_query_utils", "serve" ]