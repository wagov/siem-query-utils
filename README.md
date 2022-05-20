# siem-query-utils
General utilities for querying SIEMs, container images planned for simple deployments.

## Usage

Run the below in Azure Cloud Shell
```bash
az container create --subscription ... -g SEC-RG-Sentinel-PRD-001 --name siem-query-utils --image ghcr.io/wagov/siem-query-utils:main --assign-identity --secure-environment-variables API_TOKEN=... --ports 443 --cpu 4 --memory 4 --dns-name-label siem-query-utils
```