FROM python:3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

EXPOSE 8000


RUN useradd --create-home appuser
USER appuser
WORKDIR /home/appuser
SHELL ["/bin/bash", "--login", "-c"]
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash
RUN nvm install node
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH "$PATH:/home/appuser/.local/bin"
COPY --chown=appuser . ./app
WORKDIR /home/appuser/app
RUN poetry install 
RUN poetry run az extension add -n log-analytics -y
RUN cd atlaskit-transformer && npm install

ENTRYPOINT [ "poetry", "run", "siem_query_utils", "serve" ]