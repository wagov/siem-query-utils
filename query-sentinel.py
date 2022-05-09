#!/usr/bin/env python3
from subprocess import run, check_output
from collections import namedtuple
from pathlib import Path
import sys, json, time


def azcli(cmd, subscription=None):
    # Run a general azure cli cmd
    if subscription:
        run(f"az account set --subscription '{subscription}'", shell=True)
    result = check_output(f"az {cmd} --only-show-errors -o json", shell=True)
    if not result:
        return None
    return json.loads(result)

def analyticsQuery(query, workspace, subscription=None):
    # Run a log analytics query given a workspace (customerId) and subscription
    if subscription:
        run(f"az account set --subscription '{subscription}'", shell=True)
    result = check_output(["az", "monitor", "log-analytics", "query", "--workspace", workspace, "--analytics-query", query])
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
        return json.load(cache.open())
    else:
        subscriptions = azcli("account list --query '[].id'")
        workspaces = []
        for subscription in subscriptions:
            logAnalyticsWorkspaces = azcli("monitor log-analytics workspace list --query '[].[customerId,resourceGroup,name]'", subscription)
            for customerId, resourceGroup, name in logAnalyticsWorkspaces:
                print(len(workspaces), end=".", flush=True)
                try:
                    tables = azcli(f"monitor log-analytics workspace table list -g {resourceGroup} --workspace-name {name} --query '[].name'")
                except:
                    continue
                if "SecurityIncident" in tables:
                    try:
                        analyticsQuery('SecurityIncident | take 1', customerId, subscription)
                        workspaces.append(Workspace(subscription, customerId, resourceGroup, name))
                    except Exception as e:
                        print(f"Skipping {resourceGroup}/{name}")
                    break
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
    # TODO: use multiprocessing to make snappy
    results = []
    for workspace in listWorkspaces():
        workspace = Workspace(*workspace)
        results += analyticsQuery(query, workspace.customerId, workspace.subscription)
    return results

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
        print(f"Example: {sys.argv[0]} {actions.keys()[0]}")