# siem-query-utils
General utilities for querying SIEMs, container images planned for simple deployments.

## Usage

Run the below in Azure Cloud Shell
```bash
az container create --subscription ... -g ... --name siem-query-utils --image ghcr.io/wagov/siem-query-utils:main --assign-identity --secure-environment-variables API_TOKEN=... FQDN=uniqueapiname.australiaeast.azurecontainer.io --ports 80 443 --cpu 2 --memory 4 --dns-name-label uniqueapiname
```

For local development and debugging can use the container locally as follows (will automatically reload on code changes from current folder):
```bash
docker run -it -v $(pwd):/app -p 8000:8000 ghcr.io/wagov/siem-query-utils bash
# inside docker container (TENANT_ID is optional, but useful if e.g. one tenant has specific auth constraints).
az login --tenant $TENANT_ID
# follow auth prompts
./main.py debug
# open http://localhost:8000 in your browser
```

You can also build and test the container locally using `docker build -t <localname>; docker run -it -v $(pwd):/app -p 8000:8000 <localname>`