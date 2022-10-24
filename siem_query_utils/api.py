import base64
import hashlib
import hmac
import importlib
import json
import logging
import os
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from enum import Enum
from mimetypes import guess_type
from pathlib import Path
from string import Template
from typing import Any, Optional

import pandas
import requests
from azure.cli.core import get_default_cli
from azure.storage.blob import BlobServiceClient
from cacheout import Cache
from cloudpathlib import AzureBlobClient
from dateutil.parser import isoparse
from fastapi import BackgroundTasks, Body, FastAPI, HTTPException
from fastapi.responses import Response
from flatten_json import flatten
from markdown import markdown
from pathvalidate import sanitize_filepath

logger = logging.getLogger("uvicorn.error")

Workspace = namedtuple("Workspace", "subscription, customerId, resourceGroup, name")
cache = Cache(maxsize=25600, ttl=300)


def clean_path(path: str):
    # remove any dir traversal and dangerous chars
    return sanitize_filepath(path.replace("..", ""))


try:
    datalake_blob_prefix = os.environ["DATALAKE_BLOB_PREFIX"]  # e.g. "https://{datalake_account}.blob.core.windows.net/{datalake_container}"
    datalake_subscription = os.environ["DATALAKE_SUBSCRIPTION"]
    datalake_account, datalake_container = datalake_blob_prefix.split("/")[2:]
    datalake_account = datalake_account.split(".")[0]
except:
    raise Exception("Please set DATALAKE_BLOB_PREFIX and DATALAKE_SUBSCRIPTION env vars")

email_footer = os.environ.get("FOOTER_HTML", "Set FOOTER_HTML env var to configure this...")
max_threads = int(os.environ.get("MAX_THREADS", "20"))

app_state = {"logged_in": False, "login_time": datetime.utcnow() - timedelta(days=1)}  # last login 1 day ago to force relogin

api_1 = FastAPI(title="SIEM Query Utils API v1", version=importlib.metadata.version(__package__))
api_2 = FastAPI(title="SIEM Query Utils API v2", version=importlib.metadata.version(__package__))


class OutputFormat(str, Enum):
    json = "json"
    csv = "csv"
    list = "list"
    df = "df"


@cache.memoize(ttl=60)
def azcli(cmd: list, error_result: Any = None):
    "Run a general azure cli cmd, if as_df True return as dataframe"
    if datetime.utcnow() - app_state["login_time"] > timedelta(hours=1):
        login(refresh=True)
    elif not app_state["logged_in"]:
        login()
    cmd += ["--only-show-errors", "-o", "json"]
    cli = get_default_cli()
    logger.debug(" ".join(cmd))
    cli.invoke(cmd, out_file=open(os.devnull, "w"))
    if cli.result.error:
        logger.warning(cli.result.error)
        if error_result is not None:
            raise cli.result.error
        else:
            return error_result
    return cli.result.result


@cache.memoize(ttl=60 * 60 * 24)  # cache sas tokens 1 day
def generatesas(account=datalake_account, container=datalake_container, subscription=datalake_subscription, permissions="racwdlt", expiry_days=3):
    expiry = str(datetime.today().date() + timedelta(days=expiry_days))
    result = azcli(
        [
            "storage",
            "container",
            "generate-sas",
            "--auth-mode",
            "login",
            "--as-user",
            "--account-name",
            account,
            "-n",
            container,
            "--subscription",
            subscription,
            "--permissions",
            permissions,
            "--expiry",
            expiry,
        ]
    )
    logger.debug(result)
    return result


def BlobPath(url: str, subscription: str = ""):
    """
    Mounts a blob url using azure cli
    If called with no subscription, just returns a pathlib.Path pointing to url (for testing)
    """
    if subscription == "":
        return Path(clean_path(url))
    account, container = url.split("/")[2:]
    account = account.split(".")[0]
    sas = generatesas(account, container, subscription, expiry_days=7)
    blobclient = AzureBlobClient(blob_service_client=BlobServiceClient(account_url=url.replace(f"/{container}", ""), credential=sas))
    return blobclient.CloudPath(f"az://{container}")


def login(refresh: bool = False):
    cli = get_default_cli()
    if os.environ.get("IDENTITY_HEADER"):
        if refresh:
            cli.invoke(["logout", "--only-show-errors", "-o", "json"], out_file=open(os.devnull, "w"))
        # Use managed service identity to login
        loginstatus = cli.invoke(["login", "--identity", "--only-show-errors", "-o", "json"], out_file=open(os.devnull, "w"))
        if cli.result.error:
            # bail as we aren't able to login
            logger.error(cli.result.error)
            exit(loginstatus)
        app_state["logged_in"] = True
        app_state["login_time"] = datetime.utcnow()
    else:
        loginstatus = cli.invoke(["account", "show", "-o", "json"], out_file=open(os.devnull, "w"))
        try:
            cli.result.result["environmentName"]
            app_state["logged_in"] = True
            app_state["login_time"] = datetime.utcnow()
        except Exception as e:
            # bail as we aren't able to login
            logger.error(e)
            exit()


def loadkql(query: str):
    "If query starts with kql/ then load it from a package resource and return text"
    if query.startswith("kql/"):
        path = Path(__package__) / Path(clean_path(query))
        query = importlib.resources.read_text(package=str(path.parent).replace("/", "."), resource=path.name).strip()
    # If query starts with kql:// then load it from KQL_BASEURL
    elif query.startswith("kql://"):
        base_url = os.environ["KQL_BASEURL"]
        path = clean_path(query.replace("kql://", "", 1))
        url = f"{base_url}/{path}"
        query = requests.get(url).text.strip()
    logger.debug(f"KQL Query:\n{query}")
    return query


def analytics_query(workspaces: list, query: str, timespan: str = "P7D", groupQueries=True):
    "Queries a list of workspaces using kusto"
    query = loadkql(query)
    cmd_base = ["monitor", "log-analytics", "query", "--analytics-query", query, "--timespan", timespan]
    if groupQueries or len(workspaces) == 1:
        cmd = cmd_base + ["--workspace", workspaces[0]]
        if len(workspaces) > 1:
            cmd += ["--workspaces"] + workspaces[1:]
        try:
            return azcli(cmd, error_result="raise")  # big grouped query
        except Exception as e:
            logger.warning(e)
            logger.warning("falling back to individual queries")
            pass
    # run each query separately and stitch results, 20 at a time.
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {ws: executor.submit(azcli, cmd_base + ["--workspace", ws], error_result=[]) for ws in workspaces}
        for ws, future in futures.items():
            result = future.result()
            for item in result:
                item.update({"TenantId": ws})
            results += result
    return results


@api_2.get("/listWorkspaces")
@cache.memoize(ttl=60 * 60 * 3)  # 3 hr cache
def list_workspaces(format: OutputFormat = OutputFormat.list):
    "Get sentinel workspaces as a dataframe"
    # return workspaces dataframe from the datalake
    df = pandas.read_csv((datalake_path / "notebooks/lists/SentinelWorkspaces.csv").open()).join(
        pandas.read_csv((datalake_path / "notebooks/lists/SecOps Groups.csv").open()).set_index("Alias"), on="SecOps Group"
    )
    if format == OutputFormat.list:
        return list(df.customerId.dropna())
    elif format == OutputFormat.json:
        return df.fillna("").to_dict("records")
    elif format == OutputFormat.csv:
        return df.to_csv()
    elif format == OutputFormat.df:
        return df


@api_1.get("/simpleQuery")
def simple_query(query: str, name: str, timespan: str = "P7D"):
    "Find first workspace matching name, then run a kusto query against it"
    for workspace in list_workspaces(format=OutputFormat.json):
        if str(workspace).find(name):
            return analytics_query([workspace.customerId], query, timespan)


def upload_results(results, blobdest, filenamekeys):
    "Uploads a list of json results as individual files split by timegenerated to a blob destination"
    blobdest = clean_path(blobdest)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for result in results:
            dirname = f"{result['TimeGenerated'].split('T')[0]}"
            filename = "_".join([result[key] for key in filenamekeys.split(",")]) + ".json"
            executor.submit(datalake_json, path=f"{blobdest}/{dirname}/{filename}", content=result, modified_key="TimeGenerated")
    logger.debug(f"Uploaded {len(results)} results.")


@api_1.get("/globalQuery")
def global_query(
    query: str,
    tasks: BackgroundTasks,
    timespan: str = "P7D",
    count: bool = False,
    groupQueries: bool = True,
    blobdest: str = "",
    loganalyticsdest: str = "",
    filenamekeys: str = "",
):
    """
    Query all workspaces with SecurityIncident tables using kusto.
    If blobdest is provided as a path the first 2 segments are assumed to be the location to save results to <account>/<container>/.../<filename>
    If loganalyticsdest is provided it defines a custom log table to upload results to using the LA_CUSTOMERID and LA_SHAREDKEY env vars
    Results are saved as individual .json files, and overwritten if they already exist.
    Filenamekeys are a comma separated list of keys to build filename from
    """
    results = analytics_query(list_workspaces(), query, timespan, groupQueries=groupQueries)
    if blobdest != "":
        tasks.add_task(upload_results, results, blobdest, filenamekeys)
    if loganalyticsdest != "":
        tasks.add_task(upload_loganalytics, results, loganalyticsdest)
    if count:
        return len(results)
    else:
        return results


@api_1.get("/globalStats")
def global_stats(
    query: str,
    timespan: str = "P7D",
    count: bool = False,
    blobdest: str = "",
):
    """
    Query all workspaces with SecurityIncident tables using kusto.
    If blobdest is provided as a path the date will replace the querydate param <account>/<container>/{querydate}/<filename>
    Results are saved as a single json file intended for e.g. powerbi
    """
    results = analytics_query(list_workspaces(), query, timespan)
    if blobdest != "":
        blobdest = blobdest.format(querydate=datetime.now().date().isoformat())
        logger.info(f"Uploading to {blobdest}")
        datalake_json(blobdest, results)
    if count:
        return len(results)
    else:
        return results


email_template = Template(importlib.resources.read_text(f"{__package__}.templates", "email-template.html"))
datalake_path = BlobPath(datalake_blob_prefix, datalake_subscription)


@api_2.get("/datalake/{path:path}")
def datalake(path):
    path = datalake_path / clean_path(path)
    if not path.exists():
        logger.warning(path)
        raise HTTPException(404, f"{path} not found")
    return Response(content=path.read_bytes(), media_type=guess_type(path.name)[0])


def datalake_json(path: str, content=None, modified_key: Optional[str] = None):
    # retrieves or uploads a json file from the datalake
    path = datalake_path / clean_path(path)
    if content is None:
        return json.loads(path.read_text())
    elif modified_key and modified_key in content and path.exists():
        # Contrast the actual blob content for its modified time
        source_mtime, dest_mtime = isoparse(content[modified_key]), isoparse(json.loads(path.read_text())[modified_key])
        if source_mtime >= dest_mtime:
            return content
    logger.debug(f"Uploading {path}.")
    path.write_text(json.dumps(content, sort_keys=True, indent=2))
    return content


@api_1.get("/sentinelBeautify")
def sentinel_beautify(blob_path: str):
    """
    Takes a SecurityIncident from sentinel, and retreives related alerts and returns markdown, html and detailed json representation.
    """
    valid_prefix = "/datalake/sentinel_outputs/incidents"
    if not blob_path.startswith(valid_prefix):
        return f"Blob path must start with {valid_prefix}"
    blob_path = blob_path.replace("/datalake/", "", 1)  # strip leading /datalake/
    data = datalake_json(blob_path)
    labels = [f"SIEM_Severity:{data['Severity']}", f"SIEM_Status:{data['Status']}", f"SIEM_Title:{data['Title']}"]
    labels += [l["labelName"] for l in json.loads(data["Labels"])]  # copy over labels from incident
    incident_details = [data["Description"], ""]

    if data.get("Owner"):
        data["Owner"] = json.loads(data["Owner"])
        owner = None
        if data["Owner"].get("email"):
            owner = data["Owner"]["email"]
        elif data["Owner"].get("userPrincipalName"):
            owner = data["Owner"]["userPrincipalName"]
        if owner:
            labels.append(f"SIEM_Owner:{owner}")
            incident_details.append(f"- **Sentinel Incident Owner:** {owner}")

    if data.get("Classification"):
        labels.append(f"SIEM_Classification:{data['Classification']}")
        incident_details.append(f"- **Alert Classification:** {data['Classification']}")

    if data.get("ClassificationReason"):
        labels.append(f"SIEM_ClassificationReason:{data['ClassificationReason']}")
        incident_details.append(f"- **Alert Classification Reason:** {data['ClassificationReason']}")

    if data.get("ProviderName"):
        labels.append(f"SIEM_ProviderName:{data['ProviderName']}")
        incident_details.append(f"- **Provider Name:** {data['ProviderName']}")

    if data.get("AdditionalData"):
        data["AdditionalData"] = json.loads(data["AdditionalData"])
        if data["AdditionalData"].get("alertProductNames"):
            alertProductNames = ",".join(data["AdditionalData"]["alertProductNames"])
            labels.append(f"SIEM_alertProductNames:{alertProductNames}")
            incident_details.append(f"- **Product Names:** {alertProductNames}")
        if data["AdditionalData"].get("tactics"):
            tactics = ",".join(data["AdditionalData"]["tactics"])
            labels.append(f"SIEM_tactics:{tactics}")
            incident_details.append(f"- **[MITRE ATT&CK Tactics](https://attack.mitre.org/tactics/):** {tactics}")
        if data["AdditionalData"].get("techniques"):
            techniques = ",".join(data["AdditionalData"]["techniques"])
            labels.append(f"SIEM_techniques:{techniques}")
            incident_details.append(f"- **[MITRE ATT&CK Techniques](https://attack.mitre.org/techniques/):** {techniques}")

    comments = []
    if data.get("Comments"):
        data["Comments"] = json.loads(data["Comments"])
        if len(data["Comments"]) > 0:
            comments += ["", "## Comments"]
            for comment in data["Comments"]:
                comments += comment["message"].split("\n")
            comments += [""]

    alert_details = []
    observables = []
    entity_type_value_mappings = {
        "host": "{HostName}",
        "account": "{Name}",
        "process": "{CommandLine}",
        "file": "{Name}",
        "ip": "{Address}",
        "url": "{Url}",
        "dns": "{DomainName}",
        "registry-key": "{Hive}{Key}",
        "filehash": "{Algorithm}{Value}",
    }

    class Default(dict):
        def __missing__(self, key):
            return key

    if data.get("AlertIds") and datalake_blob_prefix:
        data["AlertIds"] = json.loads(data["AlertIds"])
        alertdata = []
        for alertid in reversed(data["AlertIds"]):  # walk alerts from newest to oldest, max 10
            # below should be able to find all the alerts from the latest day of activity
            try:
                url = f"sentinel_outputs/alerts/{data['LastActivityTime'].split('T')[0]}/{data['TenantId']}_{alertid}.json"
                alert = datalake_json(url)
            except Exception as e:  # alert may not exist on day of last activity time
                logger.warning(e)
                break
            else:
                if not alert_details:
                    alert_details += ["", "## Alert Details", f"The last day of activity (up to 20 alerts) is summarised below from newest to oldest."]
                alert_details.append(
                    f"### [{alert['AlertName']} (Severity:{alert['AlertSeverity']}) - TimeGenerated {alert['TimeGenerated']}]({alert['AlertLink']})"
                )
                alert_details.append(alert["Description"])
                for key in ["RemediationSteps", "ExtendedProperties", "Entities"]:  # entities last as may get truncated
                    if alert.get(key):
                        alert[key] = json.loads(alert[key])
                        if key == "Entities":  # add the entity to our list of observables
                            for entity in alert[key]:
                                if "Type" in entity:
                                    observable = {
                                        "type": entity["Type"],
                                        "value": entity_type_value_mappings.get(entity["Type"], "").format_map(Default(entity)),
                                    }
                                if not observable["value"]:  # dump whole dict as string if no mapping found
                                    observable["value"] = repr(entity)
                                observables.append(observable)
                        if alert[key] and isinstance(alert[key], list) and isinstance(alert[key][0], dict):
                            # if list of dicts, make a table
                            for index, entry in enumerate([flatten(item) for item in alert[key] if len(item.keys()) > 1]):
                                alert_details += ["", f"#### {key}.{index}"]
                                for entrykey, value in entry.items():
                                    if value:
                                        alert_details.append(f"- **{entrykey}:** {value}")
                        elif isinstance(alert[key], dict):  # if dict display as list
                            alert_details += ["", f"#### {key}"]
                            for entrykey, value in alert[key].items():
                                if value and len(value) < 200:
                                    alert_details.append(f"- **{entrykey}:** {value}")
                                elif value:  # break out long blocks
                                    alert_details += [f"- **{entrykey}:**", "", "```", value, "```", ""]
                        else:  # otherwise just add as separate lines
                            alert_details += ["", f"#### {key}"] + [item for item in alert[key]]
                alertdata.append(alert)
                if len(alertdata) >= 20:
                    # limit max number of alerts retreived
                    break
        data["AlertData"] = alertdata

    title = f"SIEM Detection #{data['IncidentNumber']} Sev:{data['Severity']} - {data['Title']} (Status:{data['Status']})"
    mdtext = (
        [
            f"# {title}",
            "",
            f"## [SecurityIncident #{data['IncidentNumber']} Details]({data['IncidentUrl']})",
            "",
        ]
        + incident_details
        + comments
        + alert_details
    )
    mdtext = "\n".join([str(line) for line in mdtext])
    content = markdown(mdtext, extensions=["tables"])
    html = email_template.substitute(title=title, content=content, footer=email_footer)
    # remove special chars and deduplicate labels
    labels = set("".join(c for c in label if c.isalnum() or c in ".:_") for label in labels)

    response = {
        "subject": title,
        "html": html,
        "markdown": mdtext,
        "labels": list(labels),
        "observables": [dict(ts) for ts in set(tuple(i.items()) for i in observables)],
        "sentinel_data": data,
    }
    return response


# Build the API signature
def build_la_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = "x-ms-date:" + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


ExampleQuery = Body(
    """// Example KQL query
SecurityIncident
| summarize count() by Severity
""",
    media_type="text/plain",
)


@api_2.post("/query")
def queryAll(tasks: BackgroundTasks, query: str = ExampleQuery, groupQueries: bool = True, timespan: str = "P7D", format: OutputFormat = OutputFormat.json):
    results = global_query(query, tasks, groupQueries=groupQueries, timespan=timespan)
    if format == OutputFormat.json:
        return results
    elif format in [OutputFormat.csv, OutputFormat.list]:
        return pandas.DataFrame.from_dict(results).to_csv()


@api_2.post("/collect")
def collect(table: str, tasks: BackgroundTasks, query: str = ExampleQuery, timespan: str = "P7D"):
    """
    Collects query results into a central table.
    Note that due to ingestion lag past 7 day deduplication may fail for the first few runs
    if run at intervals of less than 15 minutes.
    """
    return global_query(query, tasks, loganalyticsdest=table, timespan=timespan, count=True)


@api_2.post("/summarise")
def summarise(blobpath: str, query: str = ExampleQuery, timespan: str = "P7D"):
    return global_stats(query, blobdest=blobpath, timespan=timespan, count=True)


@api_2.post("/export")
def export(blobpath: str, filenamekeys: str, tasks: BackgroundTasks, query: str = ExampleQuery, timespan: str = "P7D"):
    return global_query(query, tasks, blobdest=blobpath, timespan=timespan, filenamekeys=filenamekeys, count=True)


@cache.memoize(ttl=60 * 60)
def data_collector(connstring=os.environ["AZMONITOR_DATA_COLLECTOR"]):
    subscription, resourcegroup, workspacename = connstring.split("/")
    az_workspace = ["--subscription", subscription, "--resource-group", resourcegroup, "--name", workspacename]
    customerId = azcli(["monitor", "log-analytics", "workspace", "show"] + az_workspace)["customerId"]
    primarySharedKey = azcli(["monitor", "log-analytics", "workspace", "get-shared-keys"] + az_workspace)["primarySharedKey"]
    return customerId, primarySharedKey


# Build and send a request to the Log Analytics POST API
def upload_loganalytics(rows: list, log_type: str):
    customerId, primarySharedKey = data_collector()
    table_name = f"{log_type}_CL"
    try:
        existing_data = analytics_query([customerId], table_name, "P7D")  # Scan past 7 days for duplicates
    except Exception as e:
        logger.warning(e)
        existing_data = []
    existing_hashes = set()
    digest_column = "_row_sha256"
    for row in existing_data:
        if isinstance(row, dict):
            hashkeys = [k for k in row.keys() if k.startswith(digest_column)]
            if len(hashkeys) == 1:
                existing_hashes.add(row[hashkeys[0]])  # collect hashes of existing data
    for item in rows:
        for key in ["TenantId", "tenant", "TimeGenerated", "RawData"]:  # rename reserved columns
            if key in item.keys():
                item[key + "_orig"] = item.pop(key)
        digest = hashlib.sha256(json.dumps(item, sort_keys=True).encode("utf8")).hexdigest()
        if digest not in existing_hashes:
            item[digest_column] = digest  # only add digest for new rows
    rows = [item for item in rows if digest_column in item.keys()]
    rowsize = len(json.dumps(rows[0]).encode("utf8"))
    chunkSize = int(20 * 1024 * 1024 / rowsize)  # 20MB max size
    chunks = [rows[x : x + chunkSize] for x in range(0, len(rows), chunkSize)]
    for rows in chunks:
        body = json.dumps(rows)  # dump new rows ready for upload
        method, content_type, resource = "POST", "application/json", "/api/logs"
        rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(body)

        logger.info(f"Uploading {content_length} bytes to {table_name}")

        signature = build_la_signature(customerId, primarySharedKey, rfc1123date, content_length, method, content_type, resource)
        uri = "https://" + customerId + ".ods.opinsights.azure.com" + resource + "?api-version=2016-04-01"
        headers = {"content-type": content_type, "Authorization": signature, "Log-Type": log_type, "x-ms-date": rfc1123date}

        response = requests.post(uri, data=body, headers=headers)
        if response.status_code >= 300:
            raise HTTPException(response.status_code, response.text)
