"""
Main api endpoints to be added to a fastapi app
"""
import base64
import hashlib
import hmac
import importlib
import io
import json
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from enum import Enum
from mimetypes import guess_type
from pathlib import Path
from typing import Optional

import httpx_cache
import pandas
import requests
from cloudpathlib import AnyPath
from dateutil.parser import isoparse
from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse, StreamingResponse

from .azcli import azcli, cache, clean_path, logger, settings
from .proxy import httpx_client

router = APIRouter()


class OutputFormat(str, Enum):
    """
    Output formats for query results
    """

    JSON = "json"
    CSV = "csv"
    LIST = "list"
    DF = "df"


@router.get("/datalake/{path:path}")
def datalake(path: str):
    """
    Downloads a file from the datalake, e.g. `notebooks/lists/SentinelWorkspaces.csv`
    """
    path = settings("datalake_path") / clean_path(path)
    if not path.exists():
        logger.warning(f"datalake {path} not found")
        raise HTTPException(404, f"{path} not found")
    return StreamingResponse(content=path.open(), media_type=guess_type(path.name)[0])


def datalake_json(path: str, content=None, modified_key: Optional[str] = None) -> dict:
    """
    Reads or writes a json file to the datalake.

    Args:
        path (str): Path to read or write.
        content (_type_, optional): Content to write. Defaults to None.
        modified_key (Optional[str], optional): Key to use for comparing the modified time.
            Defaults to None.

    Returns:
        dict: The json content.
    """
    # retrieves or uploads a json file from the datalake
    path = settings("datalake_path") / clean_path(path)
    if content is None:
        return json.loads(path.read_text())
    elif modified_key and modified_key in content and path.exists():
        # Contrast the actual blob content for its modified time
        source_mtime, dest_mtime = isoparse(content[modified_key]), isoparse(
            json.load(path.open())[modified_key]
        )
        if source_mtime >= dest_mtime:
            return content
    logger.debug(f"Uploading {path}.")
    path.write_text(json.dumps(content, sort_keys=True, indent=2))
    return content


@router.get("/loadkql", response_class=PlainTextResponse)
@cache.memoize()
def load_kql(query: str) -> str:
    """
    - If query starts with kql/ then load it from a package resource and return text
    - If query starts with kql:// then load it from {KQL_BASEURL} and return text
    """
    if query.startswith("kql/"):
        path = Path(__package__) / Path(clean_path(query))
        logger.debug(f"loading kql from {path}")
        query = importlib.resources.read_text(
            package=str(path.parent).replace("/", "."), resource=path.name
        ).strip()
    # If query starts with kql:// then load it from KQL_BASEURL
    elif query.startswith("kql://"):
        base_url = os.environ["KQL_BASEURL"]
        path = clean_path(query.replace("kql://", "", 1))
        url = f"{base_url}/{path}"
        logger.debug(f"loading kql from {url}")
        query = requests.get(url, timeout=10).text.strip()
    return query


def analytics_query(workspaces: list[str], query: str, timespan: str = "P7D", group_queries=True):
    "Queries a list of workspaces using kusto"
    query = load_kql(query)
    cmd_base = [
        "monitor",
        "log-analytics",
        "query",
        "--analytics-query",
        query,
        "--timespan",
        timespan,
    ]
    if group_queries or len(workspaces) == 1:
        cmd = cmd_base + ["--workspace", workspaces[0]]
        if len(workspaces) > 1:
            cmd += ["--workspaces"] + workspaces[1:]
        try:
            return azcli(cmd)  # big grouped query
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"{exc}: falling back to individual queries")
    # run each query separately and stitch results, 20 at a time.
    results = []
    with ThreadPoolExecutor(max_workers=settings("max_threads")) as executor:
        futures = {
            workspace: executor.submit(azcli, cmd_base + ["--workspace", workspace])
            for workspace in workspaces
        }
        for workspace, future in futures.items():
            try:
                result = future.result()
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(exc)
                result = []
            for item in result:
                item.update({"TenantId": workspace})
            results += result
    return results


@router.get("/listWorkspaces")
@cache.memoize(ttl=60 * 60 * 3)  # 3 hr cache
def list_workspaces(fmt: OutputFormat = OutputFormat.LIST):
    "Get sentinel workspaces from {datalake}/notebooks/lists/SentinelWorkspaces.csv"
    # return workspaces dataframe from the datalake
    dataframe = (
        pandas.read_csv(
            (settings("datalake_path") / "notebooks/lists/SentinelWorkspaces.csv").open()
        )
        .join(
            pandas.read_csv(
                (settings("datalake_path") / "notebooks/lists/SecOps Groups.csv").open()
            ).set_index("Alias"),
            on="SecOps Group",
            rsuffix="_secops",
        )
        .rename(columns={"SecOps Group": "alias", "Domains and IPs": "domains"})
    )
    if fmt == OutputFormat.LIST:
        return list(dataframe.customerId.dropna())
    elif fmt == OutputFormat.JSON:
        return dataframe.fillna("").to_dict("records")
    elif fmt == OutputFormat.CSV:
        return dataframe.to_csv()
    elif fmt == OutputFormat.DF:
        return dataframe


@router.get("/listDomains", response_class=PlainTextResponse)
def list_domains(agency: str, fmt="text") -> str:
    """
    Returns a list of domains for a given agency.

    Args:
        agency (str): Agency name.
        fmt (str, optional): Output format. Defaults to "text".

    Returns:
        str: List of domains.
    """
    secops = list_workspaces(OutputFormat.DF)
    secops = secops[secops.alias == agency]  # filter by agency
    workspaces = list(secops.customerId.dropna())
    if not workspaces:
        raise HTTPException(404, f"agency {agency} not found")
    existing_domains = set(str(secops.domains.dropna().sum()).strip().split("\n"))
    if existing_domains == set("0"):
        existing_domains = set()
    active_domains = set(
        pandas.DataFrame.from_records(
            analytics_query(workspaces, "kql/distinct-domains.kql")
        ).domain.values
    )
    domains = sorted(list(active_domains.union(existing_domains)))
    if fmt == "text":
        return "\n".join(domains)
    elif fmt == "json":
        return domains


def upload_results(results, blobdest, filenamekeys):
    "Uploads a list of json results as files split by timegenerated to a blob destination"
    blobdest = clean_path(blobdest)
    with ThreadPoolExecutor(max_workers=settings("max_threads")) as executor:
        for result in results:
            dirname = f"{result['TimeGenerated'].split('T')[0]}"
            filename = "_".join([result[key] for key in filenamekeys.split(",")]) + ".json"
            executor.submit(
                datalake_json,
                path=f"{blobdest}/{dirname}/{filename}",
                content=result,
                modified_key="TimeGenerated",
            )
    logger.debug(f"Uploaded {len(results)} results.")


def atlaskit_client():
    """
    Client for the atlaskit API
    """
    return httpx_cache.Client(base_url="http://127.0.0.1:3000")


class AtlaskitFmt(str, Enum):
    """
    Conversion formats for atlaskit
    """

    MARKDOWN = "md"
    JSON = "adf"
    WIKIMARKUP = "wiki"


@router.post("/atlaskit/{input}/to/{output}")
def atlaskit(
    request: Request,
    srcfmt: AtlaskitFmt,
    destfmt: AtlaskitFmt,
    body=Body("# Test Header", media_type="text/plain"),
):
    """
    Converts between atlaskit formats using js modules.
    """
    origin = atlaskit_client().post(
        f"/{srcfmt}/to/{destfmt}",
        content=body,
        headers={"content-type": request.headers["content-type"]},
    )
    return Response(status_code=origin.status_code, content=origin.content)


def build_la_signature(
    customer_id: str,
    shared_key: str,
    date: str,
    content_length: int,
    method: str,
    content_type: str,
    resource,
) -> str:
    """
    Build the signature string for the Log Analytics Data Collector API.

    Args:
        customer_id (str): The workspace ID.
        shared_key (str): The primary or the secondary Connected Sources client authentication key.
        date (str): The current date in RFC1123 format.
        content_length (int): The length of the request body in bytes.
        method (str): The HTTP method (GET, POST, etc.).
        content_type (str): The content type of the request.
        resource (str): The resource URI.

    Returns:
        str: The signature string.
    """
    x_headers = "x-ms-date:" + date
    string_to_hash = (
        method
        + "\n"
        + str(content_length)
        + "\n"
        + content_type
        + "\n"
        + x_headers
        + "\n"
        + resource
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
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
def query_all(
    query: str = ExampleQuery,
    group_queries: bool = True,
    timespan: str = "P7D",
    fmt: OutputFormat = OutputFormat.JSON,
):
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
def collect(
    table: str,
    tasks: BackgroundTasks,
    query: str = ExampleQuery,
    timespan: str = "P7D",
    target_workspace: str = None,
):
    """
    - Query all workspaces from `/listWorkspaces` using kusto.
    - Collects query results into a central {table}.
    - Note that due to ingestion lag past 7 day deduplication may fail for the first few runs
      if run at intervals of less than 15 minutes.
    - `target_workspace` is optional (will use env if not set), should be configured as
      {resourcegroup}/{workspacename} (subscription will be inferred from DATALAKE_SUBSCRIPTION)
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


def save_dataframes(path: AnyPath, obj: dict[pandas.DataFrame]):
    """
    Writes a dictionary of dataframes to a path (as zipped json).

    Args:
        path (AnyPath): Path to write to.
        obj (dict[pandas.DataFrame]): Dictionary of dataframes to write.
    """
    zip_bytes = io.BytesIO()
    now = datetime.now().timetuple()
    with zipfile.ZipFile(zip_bytes, "a") as zip_file:
        for name, dframe in obj.items():
            if dframe.shape[0] > 1:  # only analyse if there is more than one row
                dframe = dframe.loc[
                    :, (dframe != dframe.iloc[0]).any()
                ]  # throw out invariant columns
            dframe = dframe.convert_dtypes() # enhance fields where possible
            for col, dtype in zip(dframe.columns, dframe.dtypes):
                if dtype == "string":
                    for timestr in ["seen", "updated", "created", "date", "time"]:
                        if timestr in col.lower(): # enhance dates if possible
                            try:
                                dframe[col] = pandas.to_datetime(dframe[col])
                            except pandas.errors.ParserError:
                                pass
                if dtype == 'object': # simplify nested objects
                    dframe[col] = dframe[col].astype('string')
            json_info = zipfile.ZipInfo(f"{name}.json", date_time=now)
            json_str = dframe.convert_dtypes().to_json(orient="records", format_date="iso")
            zip_file.writestr(json_info, json_str, zipfile.ZIP_DEFLATED)
    logger.debug(f"Uploading zipped json to {path}")
    path.write_bytes(zip_bytes.getvalue())
    return zip_bytes.getbuffer().nbytes


def load_dataframes(path: AnyPath) -> dict[pandas.DataFrame]:
    """
    Reads a zip file containing json files into a dictionary of dataframes.

    Args:
        path (AnyPath): Path to zip file

    Returns:
        dict[pandas.DataFrame]: Dictionary of dataframes
    """
    logger.debug(f"Decompressing {path}")
    obj = {}
    with zipfile.ZipFile(path, "r") as mem_zipfile:
        for name in mem_zipfile.namelist():
            with mem_zipfile.open(name) as json_file:
                logger.debug(name)
                obj = pandas.read_json(json_file, orient="records")
    return obj


def kql2df(kql: str, timespan: str, workspaces: list[str]) -> pandas.DataFrame:
    """
    Load data from Sentinel into a dataframe.

    Args:
        kql (str): Kusto query to run.
        timespan (str): Timespan to query.
        workspaces (list[str]): List of workspaces to query.

    Returns:
        pandas.DataFrame: Dataframe of results.
    """
    table = kql.split("\n")[0].split(" ")[0].strip()
    try:
        data = analytics_query(workspaces=workspaces, query=kql, timespan=timespan)
        assert (len(data)) > 0
        data = pandas.json_normalize(data, max_level=1)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(f"{exc}: No data for {table} in {workspaces}")
        data = pandas.DataFrame.from_records([{f"{table}": f"No Data in timespan {timespan}"}])
    return data


def httpx_api(apiname: str) -> httpx_cache.Client:
    """
    Returns a httpx client for the given api configured using keyvault session.

    Args:
        apiname (str): Name of the api to use.

    Returns:
        httpx_cache.Client: httpx client for the api.
    """
    return httpx_client(settings("keyvault_session")["session"][f"proxy_{apiname}"])


def runzero2df(agency=None) -> pandas.DataFrame:
    """
    Get the runzero services for a given agency.

    Args:
        agency (str): Agency to get runzero dataframe for.

    Returns:
        pandas.DataFrame: Services for an agency as a dataframe.
    """
    if agency is None:
        params = {}
    else:
        domains = list_domains(agency).split("\n")
        query = " OR ".join([f'vhost:"{domain}"' for domain in domains])
        params = {"search": query}
    logger.debug(f"Querying runzero services: {params}")
    response = httpx_api("runzero-v1.0").get("/export/org/services.jsonl", params=params)
    rows = pandas.read_json(response.text, lines=True).to_dict(orient="records") # pylint: disable=no-member
    if len(rows) == 0:
        dframe = pandas.DataFrame.from_records(
            [{"External Internet Services": f"No Data found for {domains}"}]
        )
    else:
        dframe = pandas.json_normalize(rows, max_level=1)
    return dframe


def report_json_raw(query_config: dict, path: AnyPath, agencies: pandas.DataFrame, timespan: str):
    """
    Run a set of queries and save the results to a collection of zip files.

    Args:
        query_config (dict): Dictionary of queries to run.
        path (AnyPath): Path to save zip files to.
        agencies (pandas.DataFrame): Dataframe of agencies to query.
        timespan (str): Timespan to query.
    """
    with ThreadPoolExecutor(max_workers=settings("max_threads")) as xctr:
        for agency in agencies.alias.unique():
            jsonzip, futures = path / f"{agency}_data.zip", {}
            futures["Internet Exposed Services"] = xctr.submit(runzero2df, agency)
            for query in query_config.get("agency_sentinel", []):
                wsids = list(agencies[agencies.alias == agency].customerId.values)
                futures[query["name"]] = xctr.submit(kql2df, query["kql"], timespan, wsids)
            agency_dframes = {name: future.result() for name, future in futures.items()}
            agency_dframes["Agency Info"] = agencies[agencies.alias == agency]
            save_dataframes(jsonzip, agency_dframes)
        agency = "ALL"
        jsonzip, futures = path / f"{agency}_data.zip", {}
        futures["Internet Exposed Services"] = xctr.submit(runzero2df)
        wsids = list_workspaces(OutputFormat.LIST)
        for query in query_config.get("global_sentinel", []):
            futures[query["name"]] = xctr.submit(kql2df, query["kql"], timespan, wsids)
        save_dataframes(jsonzip, {name: future.result() for name, future in futures.items()})


@router.post("/collect_report_json")
def collect_report_json(
    tasks: BackgroundTasks,
    query_config: str = "notebooks/lists/report-queries.json",
    blobpath: str = "notebooks/query_cache",
    timespan: str = "P30D",
    limit: int = None,
):
    """
    Collects json for a report. Queries are run in parallel and the results are saved to a zip file per agency.
    The zip files are for use by the report generation notebook and by users who want an offline copy of the data.

    Args:
        tasks (BackgroundTasks): Background tasks executor.
        query_config (str, optional): Path to query config. Defaults to "notebooks/lists/report-queries.json".
        blobpath (str, optional): Path to save query results (as zipped json) to. Defaults to "notebooks/query_cache".
        timespan (str, optional): Timespan to query. Defaults to "P30D".
        limit (int, optional): Limit the number of agencies to query (for testing). Defaults to None.
    - Step through config performing per agency and global queries
    - Queries can either be log analytics or http api calls
    - Responses are parsed into dataframes, then compressed and uploaded to blob storage
    """
    query_config = datalake_json(query_config)
    agencies = list_workspaces(fmt=OutputFormat.DF).dropna(subset=["customerId", "alias"])[:limit]
    output_path = (
        settings("datalake_path") / clean_path(blobpath) / datetime.utcnow().strftime("%Y-%m")
    )
    for query in query_config.get("global_https", []):
        query["api"] = httpx_client(settings("keyvault_session")[f"proxy_{query['api']}"])
    tasks.add_task(report_json_raw, query_config, output_path, agencies, timespan)
    return {
        "agencies": agencies[["customerId", "alias"]].to_dict("records"),
        "total_queries": agencies.shape[0] * len(query_config.get("agency_sentinel", []))
        + len(query_config.get("global_sentinel", []))
        + len(query_config.get("global_https", [])),
    }


@router.post("/export")
def export(
    blobpath: str,
    filenamekeys: str,
    tasks: BackgroundTasks,
    query: str = ExampleQuery,
    timespan: str = "P7D",
):
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
def data_collector(target_workspace: str = None) -> tuple[str]:
    """
    Retreives credentials for a target workspace.

    Args:
        target_workspace (str, optional): Defaults to settings("datalake_collector_connstring").

    Returns:
        tuple[str] (customer_id, shared_key): workspace id and workspace key.
    """
    if not target_workspace:
        target_workspace = settings("data_collector_connstring")
    else:
        target_workspace = settings("datalake_subscription") + "/" + target_workspace
    subscription, resourcegroup, workspacename = target_workspace.split("/")
    az_workspace = [
        "--subscription",
        subscription,
        "--resource-group",
        resourcegroup,
        "--name",
        workspacename,
    ]
    customer_id = azcli(["monitor", "log-analytics", "workspace", "show"] + az_workspace)[
        "customerId"
    ]
    shared_key = azcli(["monitor", "log-analytics", "workspace", "get-shared-keys"] + az_workspace)[
        "primarySharedKey"
    ]
    return customer_id, shared_key


def upload_loganalytics_raw(rows, customer_id, shared_key, log_type):
    """
    Uploads json log analytics data to a workspace.
    """
    body = json.dumps(rows)  # dump new rows ready for upload
    method, content_type, resource = "POST", "application/json", "/api/logs"
    rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)

    logger.info(f"Uploading {content_length} bytes to {log_type}_CL")

    signature = build_la_signature(
        customer_id, shared_key, rfc1123date, content_length, method, content_type, resource
    )
    uri = (
        "https://"
        + customer_id
        + ".ods.opinsights.azure.com"
        + resource
        + "?api-version=2016-04-01"
    )
    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }

    response = requests.post(uri, data=body, headers=headers, timeout=120)
    if response.status_code >= 300:
        raise HTTPException(response.status_code, response.text)


@router.post("/ingest")
def upload_loganalytics(rows: list[dict], log_type: str, target_workspace: str = None):
    """
    Uploads a set of records to the {data_collector} workspace into table {log_type}_CL.
    - Deduplicates against similar data for the past 7 days using a sha256 hash of the row.
    - `target_workspace` is optional (will use env if not set), should be configured as {resourcegroup}/{workspacename}
      (subscription will be inferred from DATALAKE_SUBSCRIPTION)
    """
    customer_id, shared_key = data_collector(target_workspace)
    try:
        existing_data = analytics_query(
            [customer_id], f"{log_type}_CL", "P7D"
        )  # Scan past 7 days for duplicates
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            f"{exc}: existing table {log_type}_CL not found in {customer_id} workspace, skipping"
            " deduplication"
        )
        existing_data = []  # If we can't query, assume no duplicates
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
    with ThreadPoolExecutor(max_workers=settings("max_threads")) as executor:
        for rows in chunks:
            executor.submit(upload_loganalytics_raw, rows, customer_id, shared_key, log_type)
    logger.info(f"Uploaded {len(allrows)} records to {log_type}_CL.")
