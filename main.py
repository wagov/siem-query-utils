#!/usr/bin/env python3
import json
import os
import sys
import time
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from fire import Fire
from functools import lru_cache, wraps
from pathlib import Path
from subprocess import check_output
from typing import Union

from fastapi import FastAPI, Response, Request

secret_api_token = os.environ["API_TOKEN"]
app = FastAPI(title="SIEM Query Utils")


@app.middleware("http")
async def authenticate_request(request: Request, call_next):
    # Middleware to do a simple check of api token vs secure env var
    auth_token = request.query_params.get("auth_token", request.cookies.get("auth_token"))
    if auth_token not in [secret_api_token]:
        response = Response(content="Invalid auth_token", status_code=403, media_type="text/plain")
    else:
        response = await call_next(request)
        if request.cookies.get("auth_token") != auth_token:
            response.set_cookie("auth_token", auth_token)  # persist auth in a cookie
    return response


def cache(maxsize=2000, typed=False, ttl=300):
    """Least-recently used cache with time-to-live (ttl) limit."""

    class Result:
        __slots__ = ("value", "death")

        def __init__(self, value, death):
            self.value = value
            self.death = death

    def decorator(func):
        @lru_cache(maxsize=maxsize, typed=typed)
        def cached_func(*args, **kwargs):
            value = func(*args, **kwargs)
            death = time.monotonic() + ttl
            return Result(value, death)

        @wraps(func)
        def wrapper(*args, **kwargs):
            result = cached_func(*args, **kwargs)
            if result.death < time.monotonic():
                result.value = func(*args, **kwargs)
                result.death = time.monotonic() + ttl
            return result.value

        wrapper.cache_clear = cached_func.cache_clear
        return wrapper

    return decorator


@cache()
def azcli(*cmd):
    "Run a general azure cli cmd"
    result = check_output(["az"] + list(cmd) + ["--only-show-errors", "-o", "json"])
    if not result:
        return None
    return json.loads(result)


try:
    azcli("account", "show")
except:
    try:
        azcli("login", "--identity")
    except Exception as e:
        print(e)


def analytics_query(workspaces: list, query: str, timespan: str = "P7D"):
    "Queries a list of workspaces using kusto"
    chunkSize = 30
    chunks = [sorted(workspaces)[x : x + chunkSize] for x in range(0, len(workspaces), chunkSize)]
    results, output = [], []
    with ThreadPoolExecutor() as executor:
        for chunk in chunks:
            cmd = ["monitor", "log-analytics", "query", "--workspace", chunk[0], "--analytics-query", query, "--timespan", timespan]
            if len(chunk) > 1:
                cmd += ["--workspaces"] + chunk[1:]
            results.append(executor.submit(azcli, *cmd))
    for future in results:
        try:
            output += future.result()
        except Exception as e:
            print(e)
    return output


Workspace = namedtuple("Workspace", ["subscription", "customerId", "resourceGroup", "name"])


@app.get("/listWorkspaces")
@cache(ttl=24 * 60 * 60)  # cache workspaces for 1 day
def list_workspaces():
    "Get all workspaces as a list of named tuples"
    with ThreadPoolExecutor() as executor:
        subscriptions = azcli("account", "list", "--query", "[].id")
        wsquery = ["monitor", "log-analytics", "workspace", "list", "--query", "[].[customerId,resourceGroup,name]"]
        subscriptions = [(s, executor.submit(azcli, *list(wsquery + ["--subscription", s]))) for s in subscriptions]
    workspaces = set()
    for subscription, future in subscriptions:
        for customerId, resourceGroup, name in future.result():
            workspaces.add(Workspace(subscription, customerId, resourceGroup, name))
    # cross check workspaces to make sure they have SecurityIncident tables
    validated = analytics_query([ws.customerId for ws in workspaces], "SecurityIncident | distinct TenantId")
    validated = [item["TenantId"] for item in validated]
    return [ws for ws in workspaces if ws.customerId in validated]


@app.get("/simpleQuery")
def simple_query(query: str, name: str, timespan: str = "P7D"):
    "Find first workspace matching name, then run a kusto query against it"
    for workspace in list_workspaces():
        if str(workspace).find(name):
            return analytics_query([workspace.customerId], query, timespan)


@app.get("/globalQuery")
def global_query(query: str, timespan: str = "P7D"):
    "Query all workspaces with SecurityIncident tables using kusto"
    return analytics_query([ws.customerId for ws in list_workspaces()], query, timespan)


if __name__ == "__main__":
    Fire({"listWorkspaces": list_workspaces, "simpleQuery": simple_query, "globalQuery": global_query})
