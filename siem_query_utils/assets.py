import json

import pandas as pd
from dagster import AssetSelection, DailyPartitionsDefinition, asset, define_asset_job

three_months_ago = (pd.Timestamp.now() - pd.to_timedelta("90d")).date()
daily_partitions = DailyPartitionsDefinition(start_date=f"{three_months_ago.isoformat()}")

asset_job = define_asset_job("asset_job", AssetSelection.all(), partitions_def=daily_partitions)


@asset(partitions_def=daily_partitions, required_resource_keys={"squ"})
def jira_issues(context):
    httpx_api = context.resources.squ()["api"].httpx_api
    client = httpx_api("jira-3")

    def getissues(start_at, jql):
        response = client.get(
            "search", params={"jql": jql, "fields": "*all", "startAt": start_at, "maxResults": 100}
        ).json()
        next_start = response["startAt"] + response["maxResults"]
        total_rows = response["total"]
        if next_start > total_rows:
            next_start = total_rows
        issues = response["issues"]
        return next_start, total_rows, issues

    fromtime = pd.to_datetime(context.asset_partition_key_for_output())
    totime = fromtime + pd.to_timedelta("1d")
    jql = f"updated >= {fromtime:%Y-%m-%d} and updated < {totime:%Y-%m-%d} order by key"
    context.log.info(jql)
    start_at, total_rows = 0, -1
    dataframes = []
    while start_at != total_rows:
        start_at, total_rows, issues = getissues(start_at, jql)
        dataframes.append(pd.DataFrame(issues))
        context.log.info(f"start_at: {start_at}, total_rows: {total_rows}")
    if total_rows > 1:
        df = pd.concat(dataframes)
        df["fields"] = df["fields"].apply(json.dumps)
        return df
    else:
        return None
