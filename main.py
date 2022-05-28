#!/usr/bin/env python3
import json
import os
import sys
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from fire import Fire
from pathlib import Path
from subprocess import check_output, run
from dateutil.parser import isoparse

from fastapi import FastAPI, Response, Request, BackgroundTasks

from sqlitecache import cache, Workspace

secret_api_token = os.environ.get("API_TOKEN")
app = FastAPI(title="SIEM Query Utils")


@app.middleware("http")
async def authenticate_request(request: Request, call_next):
    # Middleware to do a simple check of api token vs secure env var
    auth_token = request.query_params.get(
        "auth_token", request.cookies.get("auth_token", "DEBUG")
    )
    if auth_token not in [secret_api_token]:
        response = Response(
            content="Invalid auth_token", status_code=403, media_type="text/plain"
        )
    else:
        response = await call_next(request)
        if request.cookies.get("auth_token") != auth_token:
            response.set_cookie("auth_token", auth_token)  # persist auth in a cookie
    return response


@cache()
def azcli(cmd: list):
    "Run a general azure cli cmd"
    cmd = ["az"] + cmd + ["--only-show-errors", "-o", "json"]
    result = check_output(cmd)
    if not result:
        return None
    return json.loads(result)


if os.environ.get("IDENTITY_HEADER"):
    # Use managed service identity to login
    try:
        azcli(["login", "--identity"])
        run(["azcopy", "login", "--identity"])
    except Exception as e:
        # bail as we aren't able to login
        print(e)
        exit()


def analytics_query(
    workspaces: list, query: str, timespan: str = "P7D", outputfilter: str = ""
):
    "Queries a list of workspaces using kusto"
    print(f"Log analytics query across {len(workspaces)} workspaces")
    chunkSize = 20  # limit to 20 parallel workspaces at a time https://docs.microsoft.com/en-us/azure/azure-monitor/logs/cross-workspace-query#cross-resource-query-limits
    chunks = [
        sorted(workspaces)[x : x + chunkSize]
        for x in range(0, len(workspaces), chunkSize)
    ]  # awesome list comprehension to break big list into chunks of chunkSize
    # chunks = [[1..10],[11..20]]
    results, cmds = [], []
    for chunk in chunks:
        cmd = [
            "monitor",
            "log-analytics",
            "query",
            "--workspace",
            chunk[0],
            "--analytics-query",
            query,
            "--timespan",
            timespan,
        ]
        if len(chunk) > 1:
            cmd += ["--workspaces"] + chunk[1:]
        if outputfilter:
            cmd += ["--query", outputfilter]
        cmds.append(cmd)
    with ThreadPoolExecutor() as executor:
        for result in executor.map(azcli, cmds):
            if result:
                results += result
    return results


@app.get("/listWorkspaces")
@cache(seconds=60 * 60 * 3)  # 3 hr cache
def list_workspaces():
    "Get sentinel workspaces as a list of named tuples"
    workspaces = azcli(
        [
            "graph",
            "query",
            "-q",
            """Resources
            | where type == 'microsoft.operationalinsights/workspaces'
            | project id, name, resourceGroup, subscription = subscriptionId, customerId = tostring(properties.customerId)
            | join (Resources
                    | where type == 'microsoft.operationsmanagement/solutions' and plan.product contains 'security'
                    | project name = tostring(split(properties.workspaceResourceId, '/')[-1])
            ) on name
            | distinct subscription, customerId, name, resourceGroup
            """,
            "--first",
            "1000",
            "--query",
            "data[]",
        ]
    )
    # subscriptions is filtered to just those with security solutions installed
    sentinelworkspaces = set()
    # TODO: page on skiptoken if total workspaces exceeds 1000
    # cross check workspaces to make sure they have SecurityIncident tables
    validated = analytics_query(
        [ws["customerId"] for ws in workspaces],
        "SecurityIncident | distinct TenantId",
        outputfilter="[].TenantId",
    )
    for ws in workspaces:
        if ws["customerId"] in validated:
            sentinelworkspaces.add(Workspace(**ws))
    return sorted(list(sentinelworkspaces))


@app.get("/simpleQuery")
def simple_query(query: str, name: str, timespan: str = "P7D"):
    "Find first workspace matching name, then run a kusto query against it"
    for workspace in list_workspaces():
        if str(workspace).find(name):
            return analytics_query([workspace.customerId], query, timespan)


def upload_results(results, blobdest, filenamekeys):
    "Uploads a list of json results as individual files split by timegenerated to a blob destination"
    account, dest = blobdest.split("/", 1)
    with tempfile.TemporaryDirectory() as tmpdir:
        dirnames = set()
        for result in results:
            dirname = f"{tmpdir}/{result['TimeGenerated'].split('T')[0]}"
            dirnames.add(dirname)
            modifiedtime = isoparse(result["TimeGenerated"])
            filename = (
                "_".join([result[key] for key in filenamekeys.split(",")]) + ".json"
            )
            if not os.path.exists(dirname):
                os.mkdir(dirname)
            with open(f"{dirname}/{filename}", "w") as jsonfile:
                json.dump(result, jsonfile, sort_keys=True, indent=2)
            os.utime(
                f"{dirname}/{filename}",
                (modifiedtime.timestamp(), modifiedtime.timestamp()),
            )
        cmds = []
        for dirname in dirnames:
            # sync each day separately to avoid listing unnecessary blobs
            cmds.append(
                [
                    "azcopy",
                    "sync",
                    dirname,
                    f"https://{account}.blob.core.windows.net/{dest}/{dirname}",
                    "--put-md5"
                ]
            )
        with ThreadPoolExecutor() as executor:
            executor.map(run, cmds)


@app.get("/globalQuery")
def global_query(
    query: str,
    tasks: BackgroundTasks,
    timespan: str = "P7D",
    count: bool = False,
    blobdest: str = "",
    filenamekeys: str = "",
):
    """
    Query all workspaces with SecurityIncident tables using kusto.
    If datalake is provided as a path the first 2 segments are assumed to be the location to save results to <account>/<container>/.../<filename>
    Results are saved as individual .json files, and overwritten if they already exist.
    Filenamekeys are a comma separated list of keys to build filename from
    """
    results = analytics_query(
        [ws.customerId for ws in list_workspaces()], query, timespan
    )
    if blobdest != "":
        tasks.add_task(upload_results, results, blobdest, filenamekeys)
    if count:
        return len(results)
    else:
        return results


def debug_server():
    "Run a debug server on localhost, port 8000 that doesn't need auth"
    import uvicorn

    azcli(["extension", "add", "-n", "log-analytics", "-y"])
    azcli(["extension", "add", "-n", "resource-graph", "-y"])
    try:
        check_output(["azcopy", "--version"])
    except:
        run(
            [
                "curl",
                "-L",
                "https://aka.ms/downloadazcopy-v10-linux",
                "-o",
                "azcopy.tar.gz",
            ]
        )
        run(
            [
                "sudo",
                "tar",
                "xvf",
                "azcopy.tar.gz",
                "-C",
                "/usr/local/bin",
                "--strip",
                "1",
                "--wildcards",
                "*/azcopy",
                "--no-same-owner",
            ]
        )
        run(["sudo", "chmod", "a+x", "/usr/local/bin/azcopy"])
        os.remove("azcopy.tar.gz")
    os.environ["API_TOKEN"] = "DEBUG"
    uvicorn.run("main:app", log_level="debug", reload=True)


if __name__ == "__main__":
    Fire(
        {
            "listWorkspaces": list_workspaces,
            "simpleQuery": simple_query,
            "globalQuery": global_query,
            "debug": debug_server,
        }
    )
elif not secret_api_token or secret_api_token == "changeme":
    exit("Please set API_TOKEN env var to run web server")
