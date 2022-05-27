#!/usr/bin/env python3
import json
import os
import sys
import time
import tempfile
from collections import namedtuple
from datetime import timedelta, datetime
from concurrent.futures import ThreadPoolExecutor
from fire import Fire
from pathlib import Path
from subprocess import check_output
from typing import Union

from fastapi import FastAPI, Response, Request

from models import Workspace, cache

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
def azcli(*cmd):
    "Run a general azure cli cmd"
    cmd = ["az"] + list(cmd) + ["--only-show-errors", "-o", "json"]
    print("Executing: " + " ".join(cmd))
    result = check_output(cmd)
    if not result:
        return None
    return json.loads(result)


if os.environ.get("IDENTITY_HEADER"):
    # Use managed service identity to login
    try:
        azcli("login", "--identity")
    except Exception as e:
        # bail as we aren't able to login
        print(e)
        exit()


def analytics_query(workspaces: list, query: str, timespan: str = "P7D"):
    "Queries a list of workspaces using kusto"
    print(f"Log analytics query across {len(list)} workspaces")
    chunkSize = 100  # limit to 100 parallel workspaces at a time https://docs.microsoft.com/en-us/azure/azure-monitor/logs/cross-workspace-query#cross-resource-query-limits
    chunks = [
        sorted(workspaces)[x : x + chunkSize]
        for x in range(0, len(workspaces), chunkSize)
    ]  # awesome list comprehension to break big list into chunks of chunkSize
    # chunks = [[1..100],[101..200]]
    results, output = [], []
    with ThreadPoolExecutor() as executor:
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
            results.append(executor.submit(azcli, *cmd))
    for future in results:
        try:
            output += future.result()
        except Exception as e:
            print(e)
    return output


@app.get("/listWorkspaces")
def list_workspaces(lastseen: int = 24):
    "Get workspaces seen in lastseen hrs as a list of named tuples"
    lastseen = datetime.now() - timedelta(hours=lastseen)
    if not Workspace.select(Workspace.seen >= lastseen).exists():
        with ThreadPoolExecutor() as executor:
            subscriptions = azcli("account", "list", "--query", "[].id")
            wsquery = [
                "monitor",
                "log-analytics",
                "workspace",
                "list",
                "--query",
                "[].[customerId,resourceGroup,name]",
            ]
            subscriptions = [
                (s, executor.submit(azcli, *list(wsquery + ["--subscription", s])))
                for s in subscriptions
            ]
        for subscription, future in subscriptions:
            for customerId, resourceGroup, name in future.result():
                Workspace.create(
                    subscription=subscription,
                    customerId=customerId,
                    resourceGroup=resourceGroup,
                    name=name,
                )
        # cross check workspaces to make sure they have SecurityIncident tables
        validated = analytics_query(
            [ws[0] for ws in Workspace.select(Workspace.customerId).tuples()],
            "SecurityIncident | distinct TenantId",
        )
        validated = frozenset([item["TenantId"] for item in validated])
        Workspace.delete().where(Workspace.customerId.not_in(validated)).execute()
        Workspace.delete().where(Workspace.seen < lastseen).execute()
    return list(Workspace.select().where(Workspace.seen >= lastseen).namedtuples())


@app.get("/simpleQuery")
def simple_query(query: str, name: str, timespan: str = "P7D"):
    "Find first workspace matching name, then run a kusto query against it"
    for workspace in list_workspaces():
        if str(workspace).find(name):
            return analytics_query([workspace.customerId], query, timespan)


@app.get("/globalQuery")
def global_query(
    query: str,
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
        accountname, container, prefix = blobdest.split("/", 2)
        if not prefix.endswith("/"):
            prefix = prefix + "/"
        with tempfile.TemporaryDirectory() as tmpdir:
            for result in results:
                dirname = f"{tmpdir}/{result['TimeGenerated'].split('T')[0]}"
                modifiedtime = datetime.fromisoformat(result["TimeGenerated"].replace("Z",""))
                filename = (
                    "_".join([result[key] for key in filenamekeys.split(",")]) + ".json"
                )
                if not os.path.exists(dirname):
                    os.mkdir(dirname)
                with open(f"{dirname}/{filename}", "w") as jsonfile:
                    json.dump(result, jsonfile, sort_keys=True, indent=2)
                os.utime(f"{dirname}/{filename}", modifiedtime.timestamp(), modifiedtime.timestamp())
            azcli( # TODO: switch to using azcopy or sync to skip stuff with same filename/timestamp
                "storage",
                "blob",
                "upload-batch",
                "-s",
                tmpdir,
                "-d",
                container,
                "--destination-path",
                prefix,
                "--account-name",
                accountname,
                "--auth-mode",
                "login",
                "--overwrite",
                "--content-type",
                "application/json",
            )
    if count:
        return len(results)
    else:
        return results


def debug_server():
    "Run a debug server on localhost, port 8000 that doesn't need auth"
    import uvicorn

    azcli("extension", "add", "-n", "log-analytics", "-y")
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
elif not secret_api_token:
    exit("Please set API_TOKEN env var to run web server")
