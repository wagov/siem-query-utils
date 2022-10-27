import base64
import hashlib
import hmac
import importlib
import json
import logging
import os
import httpx
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
from fastapi import BackgroundTasks, Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse, PlainTextResponse
from flatten_json import flatten
from markdown import markdown
from pathvalidate import sanitize_filepath

logger = logging.getLogger("uvicorn.error")

Workspace = namedtuple("Workspace", "subscription, customerId, resourceGroup, name")
cache = Cache(maxsize=25600, ttl=300)


def clean_path(path: str):
    # remove any dir traversal and dangerous chars
    return sanitize_filepath(path.replace("..", ""))


app_state = {"logged_in": False, "login_time": datetime.utcnow() - timedelta(days=1)}  # last login 1 day ago to force relogin

api_2 = FastAPI(title="SIEM Query Utils API v2", version=importlib.metadata.version(__package__))


class OutputFormat(str, Enum):
    json = "json"
    csv = "csv"
    list = "list"
    df = "df"


def bootstrap(app_state):
    try:
        prefix, subscription = os.environ["DATALAKE_BLOB_PREFIX"], os.environ["DATALAKE_SUBSCRIPTION"]
    except:
        raise Exception("Please set DATALAKE_BLOB_PREFIX and DATALAKE_SUBSCRIPTION env vars")
    account, container = prefix.split("/")[2:]
    app_state.update(
        {
            "datalake_blob_prefix": prefix,  # e.g. "https://{datalake_account}.blob.core.windows.net/{datalake_container}"
            "datalake_subscription": subscription,
            "datalake_account": account,
            "datalake_container": container,
            "email_template": Template(importlib.resources.read_text(f"{__package__}.templates", "email-template.html")),
            "datalake_path": BlobPath(prefix, subscription),
            "email_footer": os.environ.get("FOOTER_HTML", "Set FOOTER_HTML env var to configure this..."),
            "max_threads": int(os.environ.get("MAX_THREADS", "20")),
            "data_collector_connstring": os.environ.get("AZMONITOR_DATA_COLLECTOR"),  # kinda optional
        }
    )


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
    # setup all other env vars
    bootstrap(app_state)


def config(key):
    if datetime.utcnow() - app_state["login_time"] > timedelta(hours=1):
        login(refresh=True)
    elif not app_state["logged_in"]:
        login()
    return app_state[key]


@cache.memoize(ttl=60)
def azcli(cmd: list, error_result: Any = None):
    "Run a general azure cli cmd, if as_df True return as dataframe"
    assert config("logged_in")
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
def generatesas(account: str = None, container: str = None, subscription: str = None, permissions="racwdlt", expiry_days=3):
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
            account or config("datalake_account"),
            "-n",
            container or config("datalake_container"),
            "--subscription",
            subscription or config("datalake_subscription"),
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
    sas = generatesas(account, container, subscription)
    blobclient = AzureBlobClient(blob_service_client=BlobServiceClient(account_url=url.replace(f"/{container}", ""), credential=sas))
    return blobclient.CloudPath(f"az://{container}")


@api_2.get("/datalake/{path:path}")
def datalake(path: str):
    """
    Downloads a file from the datalake, e.g. `notebooks/lists/SentinelWorkspaces.csv`
    """
    path = config("datalake_path") / clean_path(path)
    if not path.exists():
        logger.warning(path)
        raise HTTPException(404, f"{path} not found")
    return StreamingResponse(content=path.open(), media_type=guess_type(path.name)[0])


def datalake_json(path: str, content=None, modified_key: Optional[str] = None):
    # retrieves or uploads a json file from the datalake
    path = config("datalake_path") / clean_path(path)
    if content is None:
        return json.loads(path.read_text())
    elif modified_key and modified_key in content and path.exists():
        # Contrast the actual blob content for its modified time
        source_mtime, dest_mtime = isoparse(content[modified_key]), isoparse(json.load(path.open())[modified_key])
        if source_mtime >= dest_mtime:
            return content
    logger.debug(f"Uploading {path}.")
    path.write_text(json.dumps(content, sort_keys=True, indent=2))
    return content


@api_2.get("/loadkql", response_class=PlainTextResponse)
def load_KQL(query: str) -> str:
    """
    - If query starts with kql/ then load it from a package resource and return text
    - If query starts with kql:// then load it from {KQL_BASEURL} and return text
    """
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
    query = load_KQL(query)
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
    with ThreadPoolExecutor(max_workers=config("max_threads")) as executor:
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
    "Get sentinel workspaces from {datalake}/notebooks/lists/SentinelWorkspaces.csv"
    # return workspaces dataframe from the datalake
    df = pandas.read_csv((config("datalake_path") / "notebooks/lists/SentinelWorkspaces.csv").open()).join(
        pandas.read_csv((config("datalake_path") / "notebooks/lists/SecOps Groups.csv").open()).set_index("Alias"), on="SecOps Group", rsuffix="_secops"
    )
    if format == OutputFormat.list:
        return list(df.customerId.dropna())
    elif format == OutputFormat.json:
        return df.fillna("").to_dict("records")
    elif format == OutputFormat.csv:
        return df.to_csv()
    elif format == OutputFormat.df:
        return df


def upload_results(results, blobdest, filenamekeys):
    "Uploads a list of json results as individual files split by timegenerated to a blob destination"
    blobdest = clean_path(blobdest)
    with ThreadPoolExecutor(max_workers=config("max_threads")) as executor:
        for result in results:
            dirname = f"{result['TimeGenerated'].split('T')[0]}"
            filename = "_".join([result[key] for key in filenamekeys.split(",")]) + ".json"
            executor.submit(datalake_json, path=f"{blobdest}/{dirname}/{filename}", content=result, modified_key="TimeGenerated")
    logger.debug(f"Uploaded {len(results)} results.")


def atlaskit_client():
    return httpx.Client(base_url="http://127.0.0.1:3000")


class atlaskitfmt(str, Enum):
    markdown = "md"
    json = "adf"
    wikimarkup = "wiki"


@api_2.post("/atlaskit/{input}/to/{output}")
def atlaskit(request: Request, input: atlaskitfmt, output: atlaskitfmt, body=Body("# Test Header", media_type="text/plain")):
    """
    Converts between atlaskit formats using js modules.
    """
    origin = atlaskit_client().post(f"/{input}/to/{output}", content=body, headers={"content-type": request.headers["content-type"]})
    return Response(status_code=origin.status_code, content=origin.content)


@api_2.get("/sentinelBeautify")
def sentinel_beautify(blob_path: str, outputformat: str = "jira", default_status: str = "Onboard: MOU (T0)", default_orgid: int = 2):
    """
    Takes a SecurityIncident from sentinel, and retreives related alerts and returns markdown, html and detailed json representation.
    """
    valid_prefix = "sentinel_outputs/incidents"
    if not blob_path.startswith(valid_prefix):
        return f"Blob path must start with {valid_prefix}"
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

    if data.get("AlertIds") and config("datalake_blob_prefix"):
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
    html = config("email_template").substitute(title=title, content=content, footer=config("email_footer"))
    # remove special chars and deduplicate labels
    labels = set("".join(c for c in label if c.isalnum() or c in ".:_") for label in labels)

    response = {
        "subject": title,
        "labels": list(labels),
        "observables": [dict(ts) for ts in set(tuple(i.items()) for i in observables)],
        "sentinel_data": data,
    }
    if outputformat == "jira":
        df = list_workspaces(OutputFormat.df)
        customer = df[df["customerId"] == data["TenantId"]].fillna('').to_dict("records")
        if len(customer) > 0:
            customer = customer[0]
        else:
            customer = {}
        # Grab wiki format for jira and truncate to 32767 chars
        response.update({
            "secops_status": customer.get("SecOps Status") or default_status,
            "jira_orgid": customer.get("JiraOrgId") or default_orgid,
            "customer": customer,
            "wikimarkup": atlaskit_client().post(f"/md/to/wiki", content=mdtext, headers={"content-type": "text/plain"}).content[:32760]
        })
    else:
        response.update({"html": html, "markdown": mdtext})
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


@api_2.get("/query")
@api_2.post("/query")
def query_all(query: str = ExampleQuery, groupQueries: bool = True, timespan: str = "P7D", format: OutputFormat = OutputFormat.json):
    """
    Query all workspaces from `/listWorkspaces` using kusto.
    """
    results = analytics_query(list_workspaces(), query, timespan, groupQueries=groupQueries)
    if format == OutputFormat.json:
        return results
    elif format in [OutputFormat.csv, OutputFormat.list]:
        return pandas.DataFrame.from_dict(results).to_csv()


@api_2.post("/collect")
def collect(table: str, tasks: BackgroundTasks, query: str = ExampleQuery, timespan: str = "P7D", target_workspace: str = None):
    """
    - Query all workspaces from `/listWorkspaces` using kusto.
    - Collects query results into a central {table}.
    - Note that due to ingestion lag past 7 day deduplication may fail for the first few runs if run at intervals of less than 15 minutes.
    - `target_workspace` is optional (will use env if not set), should be configured as {resourcegroup}/{workspacename} (subscription will be inferred from DATALAKE_SUBSCRIPTION)
    """
    results = analytics_query(list_workspaces(), query, timespan)
    tasks.add_task(upload_loganalytics, results, table, target_workspace)
    return len(results)


@api_2.post("/summarise")
def summarise(blobpath: str, query: str = ExampleQuery, timespan: str = "P7D"):
    """
    - Query all workspaces in {datalake}/notebooks/lists/SentinelWorkspaces.csv using kusto.
    - Save results to {config("datalake_path")}/{querydate}/{filename}.json
    - Results are saved as a single json file intended for e.g. powerbi
    """
    results = analytics_query(list_workspaces(), query, timespan)
    blobpath = blobpath.format(querydate=datetime.now().date().isoformat())
    logger.info(f"Uploading to {blobpath}")
    datalake_json(blobpath, results)
    return len(results)


@api_2.post("/export")
def export(blobpath: str, filenamekeys: str, tasks: BackgroundTasks, query: str = ExampleQuery, timespan: str = "P7D"):
    """
    - Query all workspaces in {config("datalake_path")}/notebooks/lists/SentinelWorkspaces.csv using kusto.
    - Save results to {config("datalake_path")}/{blobpath}/{date}/{filename}.json
    - Results are saved as individual .json files, and overwritten if they already exist.
    - Filenamekeys are a comma separated list of keys to build filename from
    """
    results = analytics_query(list_workspaces(), query, timespan)
    tasks.add_task(upload_results, results, blobpath, filenamekeys)
    return len(results)


@cache.memoize(ttl=60 * 60)
def data_collector(target_workspace: str = None):
    if not target_workspace:
        target_workspace = config("data_collector_connstring")
    else:
        target_workspace = config("datalake_subscription") + "/" + target_workspace
    subscription, resourcegroup, workspacename = target_workspace.split("/")
    az_workspace = ["--subscription", subscription, "--resource-group", resourcegroup, "--name", workspacename]
    customerId = azcli(["monitor", "log-analytics", "workspace", "show"] + az_workspace)["customerId"]
    primarySharedKey = azcli(["monitor", "log-analytics", "workspace", "get-shared-keys"] + az_workspace)["primarySharedKey"]
    return customerId, primarySharedKey


def upload_loganalytics_raw(rows, customerId, primarySharedKey, log_type):
    # Build and send a request to the Log Analytics POST API
    body = json.dumps(rows)  # dump new rows ready for upload
    method, content_type, resource = "POST", "application/json", "/api/logs"
    rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)

    logger.info(f"Uploading {content_length} bytes to {log_type}_CL")

    signature = build_la_signature(customerId, primarySharedKey, rfc1123date, content_length, method, content_type, resource)
    uri = "https://" + customerId + ".ods.opinsights.azure.com" + resource + "?api-version=2016-04-01"
    headers = {"content-type": content_type, "Authorization": signature, "Log-Type": log_type, "x-ms-date": rfc1123date}

    response = requests.post(uri, data=body, headers=headers)
    if response.status_code >= 300:
        raise HTTPException(response.status_code, response.text)


@api_2.post("/ingest")
def upload_loganalytics(rows: list[dict], log_type: str, target_workspace: str = None):
    """
    - Uploads a set of records to the {data_collector} workspace into table {log_type}_CL.
    - Deduplicates against similar data for the past 7 days using a sha256 hash of the row.
    - `target_workspace` is optional (will use env if not set), should be configured as {resourcegroup}/{workspacename} (subscription will be inferred from DATALAKE_SUBSCRIPTION)
    """
    customerId, primarySharedKey = data_collector(target_workspace)
    try:
        existing_data = analytics_query([customerId], f"{log_type}_CL", "P7D")  # Scan past 7 days for duplicates
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
    allrows = [item for item in rows if digest_column in item.keys()]
    if len(rows) == 0:
        logger.info("Nothing to upload")
        return
    rowsize = len(json.dumps(rows[0]).encode("utf8"))
    chunkSize = int(20 * 1024 * 1024 / rowsize)  # 20MB max size
    chunks = [allrows[x : x + chunkSize] for x in range(0, len(allrows), chunkSize)]
    with ThreadPoolExecutor(max_workers=config("max_threads")) as executor:
        for rows in chunks:
            executor.submit(upload_loganalytics_raw, rows, customerId, primarySharedKey, log_type)
    logger.info(f"Uploaded {len(allrows)} records to {log_type}_CL.")
