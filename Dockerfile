FROM python:3.10
LABEL org.opencontainers.image.authors="cybersecurity@dpc.wa.gov.au"
LABEL org.opencontainers.image.source="https://github.com/wagov/siem-query-utils"

EXPOSE 8000

ARG USERNAME=appuser
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Create a non-root app user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update && apt-get install -y sudo weasyprint \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME

WORKDIR /home/appuser
SHELL ["/bin/bash", "--login", "-c"]
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash
RUN nvm install 19
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH "$PATH:/home/appuser/.local/bin"
COPY --chown=appuser . ./app
RUN mkdir .azure
WORKDIR /home/appuser/app
RUN ./install.sh

ENTRYPOINT [ "/bin/bash", "--login" ]
CMD [ "-c", "poetry run siem_query_utils serve" ]