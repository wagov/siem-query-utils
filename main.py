#!/usr/bin/env python3
from typing import Union
from fastapi import FastAPI, HTTPException
from subprocess import run, check_output
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys, json, time, os

max_workers = os.environ.get("MAX_WORKERS", 32)
secret_api_token = os.environ["API_TOKEN"]

def azcli(cmd, subscription=None):
    # Run a general azure cli cmd
    if subscription:
        cmd = f"{cmd} --subscription '{subscription}'"
    result = check_output(f"az {cmd} --only-show-errors -o json", shell=True)
    if not result:
        return None
    return json.loads(result)

def analyticsQuery(query, workspace, subscription=None):
    cmd = ["az", "monitor", "log-analytics", "query", "--workspace", workspace, "--analytics-query", query]
    # Run a log analytics query given a workspace (customerId) and subscription
    if subscription:
        cmd = cmd + ["--subscription", subscription]
    result = check_output(cmd)
    if not result:
        return None
    return json.loads(result)

Workspace = namedtuple("Workspace", ["subscription", "customerId", "resourceGroup", "name"])

def listWorkspaces():
    # Get all workspaces as a list of named tuples
    p = Path(".")
    cache = p / "workspaces.json"
    cachetime = 60 * 60 # 1hr
    if cache.exists() and cache.stat().st_mtime > time.time() - cachetime:
        return [Workspace(*w) for w in json.load(cache.open())]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        subscriptions = azcli("account list --query '[].id'")
        workspaces, wstables, testqueries = [], [], []
        wsquery = "monitor log-analytics workspace list --query '[].[customerId,resourceGroup,name]'"
        subscriptions = [(s, executor.submit(azcli, wsquery, s)) for s in subscriptions]
        for subscription, future in subscriptions:
            logAnalyticsWorkspaces = future.result()
            for customerId, resourceGroup, name in logAnalyticsWorkspaces:
                workspace = Workspace(subscription, customerId, resourceGroup, name)
                wstables.append((workspace, executor.submit(azcli, f"monitor log-analytics workspace table list -g {resourceGroup} --workspace-name {name} --query '[].name'", subscription)))
        for workspace, future in wstables:
            try:
                tablenames = future.result()
            except Exception as e:
                continue
            if "SecurityIncident" in tablenames:
                testqueries.append((workspace, executor.submit(analyticsQuery, 'SecurityIncident | take 1', workspace.customerId, workspace.subscription)))
        for workspace, future in testqueries:
            try:
                future.result()
                workspaces.append(workspace)
            except Exception as e:
                print(f"Skipping {workspace} error {e}")
    json.dump(workspaces, cache.open("w"))
    return workspaces

def simpleQuery(query, name):
    # Find first workspace matching name, then run a kusto query against it
    for workspace in listWorkspaces():
        if str(workspace).find(name):
            workspace = Workspace(*workspace)
            return analyticsQuery(query, workspace.customerId, workspace.subscription)

def globalQuery(query):
    # Run query against all workspaces
    futures = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyticsQuery, query, w.customerId, w.subscription) for w in listWorkspaces()]
    # unwrap nested results (each query returns a json fragment)
    return [result for future in futures for result in future.result()]

actions = {
    "listWorkspaces": listWorkspaces,
    "globalQuery": globalQuery,
    "simpleQuery": simpleQuery
}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        actionName = sys.argv[1]
        args = sys.argv[2:]
        azcli("config set extension.use_dynamic_install=yes_without_prompt")
        print(actions[actionName](*args))
    else:
        print(f"Run an action from {actions.keys()}")
        print(f"Example: {sys.argv[0]} {list(actions.keys())[0]}")

app = FastAPI()

@app.get("/{actionName}")
def get_action(actionName: str, auth_token: str, args: Union[str, None] = None):
    if secret_api_token != auth_token:
        raise HTTPException(status_code=403, detail="Invalid auth_token") 
    args = json.loads(args)
    return actions[actionName](*args)