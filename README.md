# siem-query-utils
General utilities for querying SIEMs, container images planned for simple deployments.

## Usage

Run the below in Azure Cloud Shell
```bash
az container create --subscription ... -g ... --name siem-query-utils --image ghcr.io/wagov/siem-query-utils:main --assign-identity --secure-environment-variables API_TOKEN=... --ports 443 --cpu 2 --memory 4 --dns-name-label siem-query-utils
```

## Roadmap

Improve state management and caching using https://litestream.io/guides/azure/ and https://fastapi.tiangolo.com/tutorial/sql-databases/
Make sure all state loaded/saved from snapshots on blob storage so database is temporary/local for life of container only.
