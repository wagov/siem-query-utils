# pylint: disable=logging-fstring-interpolation, unspecified-encoding, line-too-long, missing-function-docstring
import base64
import hashlib
import hmac
import importlib
import json
import logging
import lzma
import os
from collections import namedtuple, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from enum import Enum
from mimetypes import guess_type
from pathlib import Path
import pickle
from string import Template
from typing import Any, Optional

import httpx
import pandas
import requests
from azure.cli.core import get_default_cli
from azure.storage.blob import BlobServiceClient
from cacheout import Cache
from cloudpathlib import AzureBlobClient, AnyPath
from dateutil.parser import isoparse
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Body, APIRouter, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse, StreamingResponse

from pathvalidate import sanitize_filepath

load_dotenv()


logger = logging.getLogger("uvicorn.error")

Workspace = namedtuple("Workspace", "subscription, customerId, resourceGroup, name")
cache = Cache(maxsize=25600, ttl=300)


def clean_path(path: str):
    # remove any dir traversal and dangerous chars
    return sanitize_filepath(path.replace("..", ""), platform="auto")


app_state = {"logged_in": False, "login_time": datetime.utcnow() - timedelta(days=1)}  # last login 1 day ago to force relogin

router = APIRouter()


class OutputFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
    LIST = "list"
    DF = "df"


def bootstrap(_app_state):
    try:
        prefix, subscription = os.environ["DATALAKE_BLOB_PREFIX"], os.environ["DATALAKE_SUBSCRIPTION"]
    except Exception as exc:
        raise Exception("Please set DATALAKE_BLOB_PREFIX and DATALAKE_SUBSCRIPTION env vars") from exc
    account, container = prefix.split("/")[2:]
    _app_state.update(
        {
            "datalake_blob_prefix": prefix,  # e.g. "https://{datalake_account}.blob.core.windows.net/{datalake_container}"
            "datalake_subscription": subscription,
            "datalake_account": account,
            "datalake_container": container,
            "email_template": Template(importlib.resources.read_text(f"{__package__}.templates", "email-template.html")),
            "datalake_path": get_blob_path(prefix, subscription),
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
            assert "environmentName" in cli.result.result
            app_state["logged_in"] = True
            app_state["login_time"] = datetime.utcnow()
        except AssertionError as exc:
            # bail as we aren't able to login
            logger.error(exc)
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
        if error_result is None:
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


def get_blob_path(url: str, subscription: str = ""):
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


@router.get("/datalake/{path:path}")
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


@router.get("/loadkql", response_class=PlainTextResponse)
def load_kql(query: str) -> str:
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
        query = requests.get(url, timeout=10).text.strip()
    logger.debug(f"KQL Query:\n{query}")
    return query


def analytics_query(workspaces: list, query: str, timespan: str = "P7D", group_queries=True):
    "Queries a list of workspaces using kusto"
    query = load_kql(query)
    cmd_base = ["monitor", "log-analytics", "query", "--analytics-query", query, "--timespan", timespan]
    if group_queries or len(workspaces) == 1:
        cmd = cmd_base + ["--workspace", workspaces[0]]
        if len(workspaces) > 1:
            cmd += ["--workspaces"] + workspaces[1:]
        try:
            return azcli(cmd, error_result="raise")  # big grouped query
        except Exception as exc:
            logger.warning(exc)
            logger.warning("falling back to individual queries")
    # run each query separately and stitch results, 20 at a time.
    results = []
    with ThreadPoolExecutor(max_workers=config("max_threads")) as executor:
        futures = {workspace: executor.submit(azcli, cmd_base + ["--workspace", workspace], error_result=[]) for workspace in workspaces}
        for workspace, future in futures.items():
            result = future.result()
            for item in result:
                item.update({"TenantId": workspace})
            results += result
    return results


@router.get("/listWorkspaces")
@cache.memoize(ttl=60 * 60 * 3)  # 3 hr cache
def list_workspaces(fmt: OutputFormat = OutputFormat.LIST):
    "Get sentinel workspaces from {datalake}/notebooks/lists/SentinelWorkspaces.csv"
    # return workspaces dataframe from the datalake
    dataframe = pandas.read_csv((config("datalake_path") / "notebooks/lists/SentinelWorkspaces.csv").open()).join(
        pandas.read_csv((config("datalake_path") / "notebooks/lists/SecOps Groups.csv").open()).set_index("Alias"), on="SecOps Group", rsuffix="_secops"
    )
    if fmt == OutputFormat.LIST:
        return list(dataframe.customerId.dropna())
    elif fmt == OutputFormat.JSON:
        return dataframe.fillna("").to_dict("records")
    elif fmt == OutputFormat.CSV:
        return dataframe.to_csv()
    elif fmt == OutputFormat.DF:
        return dataframe


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


class AtlaskitFmt(str, Enum):
    MARKDOWN = "md"
    JSON = "adf"
    WIKIMARKUP = "wiki"


@router.post("/atlaskit/{input}/to/{output}")
def atlaskit(request: Request, srcfmt: AtlaskitFmt, destfmt: AtlaskitFmt, body=Body("# Test Header", media_type="text/plain")):
    """
    Converts between atlaskit formats using js modules.
    """
    origin = atlaskit_client().post(f"/{srcfmt}/to/{destfmt}", content=body, headers={"content-type": request.headers["content-type"]})
    return Response(status_code=origin.status_code, content=origin.content)




# Build the API signature
def build_la_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = "x-ms-date:" + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {customer_id}:{encoded_hash}"
    return authorization


ExampleQuery = Body(
    """// Example KQL query
SecurityIncident
| summarize count() by Severity
""",
    media_type="text/plain",
)


@router.get("/query")
@router.post("/query")
def query_all(query: str = ExampleQuery, group_queries: bool = True, timespan: str = "P7D", fmt: OutputFormat = OutputFormat.JSON):
    """
    Query all workspaces from `/listWorkspaces` using kusto.
    """
    results = analytics_query(list_workspaces(), query, timespan, group_queries=group_queries)
    if fmt == OutputFormat.JSON:
        return results
    elif fmt in [OutputFormat.CSV, OutputFormat.LIST]:
        return pandas.DataFrame.from_dict(results).to_csv()
    elif fmt == OutputFormat.DF:
        return pandas.DataFrame.from_dict(results)


@router.post("/collect")
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


@router.post("/summarise")
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


def compress_pickle(obj, path: AnyPath):
    logger.debug(f"Compressing {path}")
    path.write_bytes(lzma.compress(pickle.dumps(obj)))


def decompress_pickle(path: AnyPath):
    logger.debug(f"Decompressing {path}")
    return pickle.loads(lzma.decompress(path.read_bytes()))


def sentinel_to_dataframe(kql: str, timespan: str, workspaces: list[str]):
    # Load or directly query kql against workspaces
    # Parse results as json and return as a dataframe
    table = kql.split("\n")[0].split(" ")[0].strip()
    try:
        data = analytics_query(workspaces=workspaces, query=kql, timespan=timespan)
        assert (len(data)) > 0
    except Exception as exc:
        logger.warning(exc)
        data = [{f"{table}": f"No Data in timespan {timespan}"}]
    dataframe = pandas.DataFrame.from_records(data)
    dataframe = dataframe[dataframe.columns].apply(pandas.to_numeric, errors="ignore")
    if "TimeGenerated" in dataframe.columns:
        dataframe["TimeGenerated"] = pandas.to_datetime(dataframe["TimeGenerated"])
    dataframe = dataframe.convert_dtypes()
    return dataframe


def external_api(client, path: str, args: dict):
    response = client.get(url=path, **args)
    return {"status_code": response.status_code, "headers": dict(response.headers), "content": response.content}


def collect_dataframes_raw(query_config: dict, output_folder: AnyPath, agencies: pandas.DataFrame, timespan: str):
    agency_sentinel = defaultdict(dict)
    with ThreadPoolExecutor(max_workers=config("max_threads")) as executor:
        for agency in agencies.alias.unique():
            agency_sentinel = {}
            for query in query_config.get("agency_sentinel", []):
                agency_sentinel[query["name"]] = executor.submit(
                    sentinel_to_dataframe, query["kql"], timespan, agencies[agencies.alias == agency].customerId.values
                )
            executor.submit(compress_pickle, {k: v.result() for k, v in agency_sentinel.items()}, output_folder / f"{agency}_sentinel.pkl.lzma")
        global_sentinel = {}
        for query in query_config.get("global_sentinel", []):
            global_sentinel[query["name"]] = executor.submit(query_all, query=query["kql"], group_queries=True, fmt=OutputFormat.DF, timespan=timespan)
        executor.submit(compress_pickle, {k: v.result() for k, v in global_sentinel.items()}, output_folder / "global_sentinel.pkl.lzma")
        global_https = {}
        for query in query_config.get("global_https", []):
            global_https[query["name"]] = executor.submit(external_api, query["api"], query["path"], query.get("args", {}))
        executor.submit(compress_pickle, {k: v.result() for k, v in global_https.items()}, output_folder / "global_https.pkl.lzma")


@router.post("/collect_dataframes")
def collect_dataframes(
    tasks: BackgroundTasks, query_config: str = "notebooks/lists/report-queries.json", blobpath: str = "notebooks/query_cache", timespan: str = "P30D"
):
    """
    - Step through config performing per agency and global queries
    - Queries can either be log analytics or http api calls
    - Responses are parsed as json and converted to dataframes, then compressed and uploaded to blob storage
    """
    query_config = datalake_json(query_config)
    agencies = list_workspaces(fmt=OutputFormat.DF).rename(columns={"SecOps Group": "alias"})
    agencies = agencies[["customerId", "alias"]].dropna()
    output_folder = config("datalake_path") / clean_path(blobpath) / datetime.utcnow().strftime("%Y-%m")
    if "global_https" in query_config:
        from .proxy import load_session, httpx_client
        proxies = load_session()
        for query in query_config["global_https"]:
            query["api"] = httpx_client(proxies["session"][f"proxy_{query['api']}"])
    tasks.add_task(collect_dataframes_raw, query_config, output_folder, agencies, timespan)
    return {
        "agencies": agencies.to_dict("records"),
        "total_queries": agencies.shape[0] * len(query_config.get("agency_sentinel", []))
        + len(query_config.get("global_sentinel", []))
        + len(query_config.get("global_https", [])),
    }


@router.post("/export")
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
    customer_id = azcli(["monitor", "log-analytics", "workspace", "show"] + az_workspace)["customerId"]
    shared_key = azcli(["monitor", "log-analytics", "workspace", "get-shared-keys"] + az_workspace)["primarySharedKey"]
    return customer_id, shared_key


def upload_loganalytics_raw(rows, customer_id, shared_key, log_type):
    # Build and send a request to the Log Analytics POST API
    body = json.dumps(rows)  # dump new rows ready for upload
    method, content_type, resource = "POST", "application/json", "/api/logs"
    rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)

    logger.info(f"Uploading {content_length} bytes to {log_type}_CL")

    signature = build_la_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = "https://" + customer_id + ".ods.opinsights.azure.com" + resource + "?api-version=2016-04-01"
    headers = {"content-type": content_type, "Authorization": signature, "Log-Type": log_type, "x-ms-date": rfc1123date}

    response = requests.post(uri, data=body, headers=headers, timeout=120)
    if response.status_code >= 300:
        raise HTTPException(response.status_code, response.text)


@router.post("/ingest")
def upload_loganalytics(rows: list[dict], log_type: str, target_workspace: str = None):
    """
    - Uploads a set of records to the {data_collector} workspace into table {log_type}_CL.
    - Deduplicates against similar data for the past 7 days using a sha256 hash of the row.
    - `target_workspace` is optional (will use env if not set), should be configured as {resourcegroup}/{workspacename} (subscription will be inferred from DATALAKE_SUBSCRIPTION)
    """
    customer_id, shared_key = data_collector(target_workspace)
    try:
        existing_data = analytics_query([customer_id], f"{log_type}_CL", "P7D")  # Scan past 7 days for duplicates
    except Exception as exc:
        logger.warning(exc)
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
    chunk_size = int(20 * 1024 * 1024 / rowsize)  # 20MB max size
    chunks = [allrows[x : x + chunk_size] for x in range(0, len(allrows), chunk_size)]
    with ThreadPoolExecutor(max_workers=config("max_threads")) as executor:
        for rows in chunks:
            executor.submit(upload_loganalytics_raw, rows, customer_id, shared_key, log_type)
    logger.info(f"Uploaded {len(allrows)} records to {log_type}_CL.")
