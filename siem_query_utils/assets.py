from .api import httpx_api
from dagster import asset

client = httpx_api("jira-3")


@asset
def issues():
    response = client.get("search", params={"fields": "*all", "maxResults": 100}).json()
    next_start = response["startAt"] + response["maxResults"]
    total_rows = response["total"]
    if next_start > total_rows:
        next_start = total_rows
    issues = response["issues"]
    return issues
