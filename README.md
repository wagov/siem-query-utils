# siem-query-utils
General utilities for querying SIEMs, container images planned for simple deployments.

## Usage

Run the below in Azure Cloud Shell
```bash
az container create --subscription ... -g ... --name siem-query-utils --image ghcr.io/wagov/siem-query-utils:main --assign-identity --secure-environment-variables API_TOKEN=... FQDN=uniqueapiname.australiaeast.azurecontainer.io --ports 80 443 --cpu 2 --memory 4 --dns-name-label uniqueapiname
```

