import json
import pandas as pd

from prefect import flow, task
from siem_query_utils.api import httpx_api


@task
def getissues(start_at, jql):
    client = httpx_api("jira-3")
    response = client.get(
        "search", params={"jql": jql, "fields": "*all", "startAt": start_at, "maxResults": 100}
    ).json()
    next_start = response["startAt"] + response["maxResults"]
    total_rows = response["total"]
    if next_start > total_rows:
        next_start = total_rows
    issues = response["issues"]
    print(total_rows, next_start)
    return next_start, total_rows, issues


@flow
def jira_issues(fromtime: str):
    fromtime = pd.to_datetime(fromtime)
    totime = fromtime + pd.to_timedelta("1d")
    jql = f"updated >= {fromtime:%Y-%m-%d} and updated < {totime:%Y-%m-%d} order by key"
    start_at, total_rows = 0, -1
    dataframes = []
    while start_at != total_rows:
        start_at, total_rows, issues = getissues.submit(start_at, jql).result()
        print(start_at, total_rows, len(issues))
        dataframes.append(pd.DataFrame(issues))
    if total_rows > 1:
        df = pd.concat(dataframes)
        df["fields"] = df["fields"].apply(json.dumps)
        return df
    else:
        return None
