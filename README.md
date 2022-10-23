# siem-query-utils

General utilities for querying SIEMs developed using [FastAPI](https://fastapi.tiangolo.com/) built ontop of [python:3.10](https://github.com/docker-library/python/blob/master/3.10/bullseye/Dockerfile). This container supports direct execution using [python-fire](https://github.com/google/python-fire) and a local webserver run on [uvicorn](https://www.uvicorn.org/#uvicornrun) using `siem_query_utils serve`.

High cost functions are cached using [cacheout](https://github.com/dgilland/cacheout) which significantly improves performance by defaulting to caching all [azure cli](https://pypi.org/project/azure-cli/) calls in memory for 5 minutes.

## Usage

The [container image](https://github.com/wagov/siem-query-utils/pkgs/container/siem-query-utils) is intended to be hosted using a runtime such as [Azure App Service (Custom Container)](https://learn.microsoft.com/en-us/azure/app-service/tutorial-custom-container?pivots=container-linux). A [Managed Identity](https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity) is required to be configured to ensure the container can login to the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-managed-identity). [example_env](example_env) should be populated and used as a local `.env` file within this repository or configured on your container hosting environment.

```bash
# Azure CLI quickstart
az webapp create --name <APP_NAME> --resource-group myRG --plan myPremiumPlan --deployment-container-image-name ghcr.io/wagov/siem-query-utils:v1.3.6
# Login to portal and configure env vars (these are needed for container to start)
```

## Development

For local development and interactive debugging run as follows (requires python 3.10 and [poetry](https://python-poetry.org/docs/#installing-with-the-official-installer)):

```bash
curl -sSL https://install.python-poetry.org | python3 -
poetry install
az login --tenant $TENANT_ID
# follow auth prompts
poetry run siem_query_utils serve
```

After running the above you can open [/api/v1/docs](http://localhost:8000/api/v1/docs) in your browser to get to the swagger debug ui which lets you test all the endpoints.

You can also build and test the container locally using docker.

```bash
docker build -t squ .; docker run --env-file .env -p 8000:8000 --entrypoint /bin/bash -it squ
# inside docker container (--tenant is optional, but useful if e.g. one tenant has specific auth constraints).
az login --tenant $TENANT_ID
# follow auth prompts
poetry run siem_query_utils serve
`````
