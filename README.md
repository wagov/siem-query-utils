# siem-query-utils

General utilities for querying SIEMs developed using [FastAPI](https://fastapi.tiangolo.com/) built ontop of [jupyter-datascience:python-3.10](https://jupyter-docker-stacks.readthedocs.io/en/latest/using/selecting.html#jupyter-datascience-notebook). This container supports direct execution using [python-fire](https://github.com/google/python-fire) and a local webserver run on [uvicorn](https://www.uvicorn.org/#uvicornrun) using `siem_query_utils serve`.

High cost functions are cached using [cacheout](https://github.com/dgilland/cacheout) which significantly improves performance by defaulting to caching all [azure cli](https://pypi.org/project/azure-cli/) calls in memory for 5 minutes.

## Roadmap

- Separate report logic entirely to [quarto](https://quarto.org) process
- Review / replace job execution logic with [prefect](https://www.prefect.io) to reduce [complexity](https://www.prefect.io/guide/videos/eliminate-negative-engineering-with-prefect/)
- Improve standalone running options and documention for running in a jupyterlab environment for secops and incident response

## Usage

The [container image](https://github.com/wagov/siem-query-utils/pkgs/container/siem-query-utils) is intended to be hosted using a runtime such as [Azure App Service (Custom Container)](https://learn.microsoft.com/en-us/azure/app-service/tutorial-custom-container?pivots=container-linux). A [Managed Identity](https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity) is required to be configured to ensure the container can login to the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-managed-identity). [example_env](example_env) should be populated and used as a local `.env` file within this repository or configured on your container hosting environment.

```bash
# Azure CLI quickstart
az webapp create --name <APP_NAME> --resource-group myRG --plan myPremiumPlan --deployment-container-image-name ghcr.io/wagov/siem-query-utils:v1.3.6
# Login to portal and configure env vars (these are needed for container to start)
```

## Development

For local development under macOS and interactive debugging run as follows (requires python 3.10):

```bash
# macOS prerequisites
brew install quarto weasyprint wkhtmltopdf jupyterlab
# Install python dependencies
pip3 install .
# Install using poetry so project is editable
poetry install
# Login to azure cli (tenant is optional, but useful if e.g. one tenant has specific auth constraints).
az login --tenant $TENANT_ID
# Run the basic service api
siem_query_utils serve
# Run a jupyter lab instance in the project directory
jupyter lab
```

If you are using github codespaces, quickstart below:

```bash
# Jupyter lab in project
poetry run siem_query_utils jupyterlab /workspace
# API endpoints
poetry run siem_query_utils serve
# Debug shell and reloading latest tickets
poetry run ipython
from siem_query_utils import api
# update_jira_issues needs the node server running background (in a bash terminal run `node .`)
api.update_jira_issues()
```

After running the above you can open [/api/v1/docs](http://localhost:8000/api/v1/docs) in your browser to get to the swagger debug ui which lets you test all the endpoints.

You can also build and test the container locally using docker.

```bash
docker build -t squ .; docker run --env-file .env -p 8000:8000 --entrypoint /bin/bash -it squ
# inside docker container (--tenant is optional, but useful if e.g. one tenant has specific auth constraints).
poetry run az login --tenant $TENANT_ID
# follow auth prompts
poetry run siem_query_utils serve
`````
