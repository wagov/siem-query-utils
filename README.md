# siem-query-utils
General utilities for querying SIEMs developed using [FastAPI](https://fastapi.tiangolo.com/) built ontop of [azure-functions/python:4-python3.10](https://mcr.microsoft.com/en-us/product/azure-functions/python/about). This container supports direct execution using [python-fire](https://github.com/google/python-fire), a local webserver run on [gunicorn](startup.sh) or a serverless [Azure Function](https://docs.microsoft.com/en-us/azure/azure-functions/functions-overview).

High cost functions are cached using [cacheout](https://github.com/dgilland/cacheout) which significantly improves performance when running long lived instances such as [Dedicated hosting plans for Azure Functions](https://docs.microsoft.com/en-us/azure/azure-functions/dedicated-plan) by defaulting to caching all [azure cli](https://pypi.org/project/azure-cli/) calls in memory for 5 minutes.

## Usage

The [container image](https://github.com/wagov/siem-query-utils/pkgs/container/siem-query-utils) is intended to be hosted using a serverless runtime such as [Azure Functions (Custom Linux Image)](https://docs.microsoft.com/en-us/azure/azure-functions/functions-create-function-linux-custom-image?tabs=in-process%2Cbash%2Cazure-cli&pivots=programming-language-other#create-and-configure-a-function-app-on-azure-with-the-image). A [Managed Identity](https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity) is required to be configured to ensure the container can login to the [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-managed-identity).

```bash
# Azure CLI quickstart
az functionapp create --name <APP_NAME> --storage-account <STORAGE_NAME> --resource-group AzureFunctionsContainers-rg --plan myPremiumPlan --deployment-container-image-name ghcr.io/wagov/siem-query-utils:v1.1.1
# Login to portal and configure DATALAKE_ env vars (these are needed for container to start)
```

## Development
For local development and interactive debugging run as follows (will automatically reload on code changes from current folder):
```bash
docker run -it -v $(pwd):/app -e DATALAKE_SUBSCRIPTION="{subscription}" -e DATALAKE_BLOB_PREFIX="https://{account}.blob.core.windows.net/{container}" -p 8000:8000 ghcr.io/wagov/siem-query-utils bash
# inside docker container (--tenant is optional, but useful if e.g. one tenant has specific auth constraints).
az login --tenant $TENANT_ID
# follow auth prompts
./main.py debug
```
After running the above you can open http://localhost:8000/api/v1/docs in your browser to get to the swagger debug ui which lets you test all the endpoints.

You can also build and test the container locally using 

```bash
docker build -t queryutils .; docker run -it -e DATALAKE_SUBSCRIPTION="{subscription}" -e DATALAKE_BLOB_PREFIX="https://{account}.blob.core.windows.net/{container}" -p 8000:8000 queryutils bash
# inside docker container (--tenant is optional, but useful if e.g. one tenant has specific auth constraints).
az login --tenant $TENANT_ID
# follow auth prompts
./startup.sh
`````