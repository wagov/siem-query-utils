import base64
import hashlib
import hmac
import json
import os
import tempfile
import logging
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from importlib.resources import read_text
from pathlib import Path
from string import Template
from subprocess import check_output, run

import requests
from cacheout import Cache
from dateutil.parser import isoparse
from fastapi import BackgroundTasks, FastAPI, HTTPException
from flatten_json import flatten
from markdown import markdown
from pathvalidate import sanitize_filepath

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

app_state = {"logged_in": False, "login_time": datetime.utcnow() - timedelta(days=1)}  # last login 1 day ago to force relogin

app = FastAPI(title="SIEM Query Utils")


@cache.memoize(ttl=60)
def azcli(cmd: list):
    "Run a general azure cli cmd"
    if datetime.utcnow() - app_state["login_time"] > timedelta(hours=1):
        login(refresh=True)
    elif not app_state["logged_in"]:
        login()
    cmd = ["az"] + cmd + ["--only-show-errors", "-o", "json"]
    logging.debug(" ".join(cmd))
    result = False
    try:
        result = check_output(cmd)
    except Exception as e:
        logging.error(e)
    if not result:
        return None
    return json.loads(result)


@cache.memoize(ttl=60 * 60 * 24)  # cache sas tokens 1 day
def generatesas(account=datalake_account, container=datalake_container, subscription=datalake_subscription, permissions="racwdlt", expiry_days=3):
    expiry = str(datetime.today().date() + timedelta(days=expiry_days))
    return azcli(
        [
            "storage",
            "container",
            "generate-sas",
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


def login(refresh: bool = False):
    if os.environ.get("IDENTITY_HEADER"):
        if refresh:
            try:
                check_output(["az", "logout", "--only-show-errors", "-o", "json"])
            except Exception as e:
                pass
        # Use managed service identity to login
        try:
            check_output(["az", "login", "--identity", "--only-show-errors", "-o", "json"])
            app_state["logged_in"] = True
            app_state["login_time"] = datetime.utcnow()
        except Exception as e:
            # bail as we aren't able to login
            logging.error(e)
            exit()
    else:
        try:
            check_output(["az", "account", "show"])
            app_state["logged_in"] = True
            app_state["login_time"] = datetime.utcnow()
        except Exception as e:
            # bail as we aren't able to login
            logging.error(e)
            exit()


def loadkql(query: str):
    "If query starts with kql/ then load it from a package resource and return text"
    if query.startswith("kql/"):
        path = Path(__package__) / Path(clean_path(query))
        query = read_text(package=str(path.parent).replace("/", "."), resource=path.name).strip()
    # If query starts with kql:// then load it from KQL_BASEURL
    elif query.startswith("kql://"):
        base_url = os.environ["KQL_BASEURL"]
        path = clean_path(query.replace("kql://", "", 1))
        url = f"{base_url}/{path}"
        query = requests.get(url).text.strip()
    logging.info(query)
    return query


def analytics_query(workspaces: list, query: str, timespan: str = "P7D", outputfilter: str = ""):
    "Queries a list of workspaces using kusto"
    query = loadkql(query)
    chunkSize = 20  # limit to 20 parallel workspaces at a time https://docs.microsoft.com/en-us/azure/azure-monitor/logs/cross-workspace-query#cross-resource-query-limits
    chunks = [
        sorted(workspaces)[x : x + chunkSize] for x in range(0, len(workspaces), chunkSize)
    ]  # awesome list comprehension to break big list into chunks of chunkSize
    logging.info(f"Log analytics query across {len(workspaces)} workspace(s) ({len(chunks)} chunks).")
    # chunks = [[1..10],[11..20]]
    results, cmds = [], []
    for chunk in chunks:
        cmd = ["monitor", "log-analytics", "query", "--workspace", chunk[0], "--analytics-query", query, "--timespan", timespan]
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
@cache.memoize(ttl=60 * 60 * 3)  # 3 hr cache
def list_workspaces():
    "Get sentinel workspaces as a list of named tuples"
    workspaces = azcli(["graph", "query", "-q", loadkql("kql/graph-workspaces.kql"), "--first", "1000", "--query", "data[]"])
    # subscriptions is filtered to just those with security solutions installed
    sentinelworkspaces = set()
    # TODO: page on skiptoken if total workspaces exceeds 1000
    # cross check workspaces to make sure they have SecurityIncident tables
    validated = analytics_query(
        [ws["customerId"] for ws in workspaces],
        "kql/distinct-tenantids.kql",
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
    blobdest = clean_path(blobdest)
    with tempfile.TemporaryDirectory() as tmpdir:
        dirnames = set()
        for result in results:
            dirname = f"{result['TimeGenerated'].split('T')[0]}"
            dirnames.add(dirname)
            modifiedtime = isoparse(result["TimeGenerated"])
            filename = "_".join([result[key] for key in filenamekeys.split(",")]) + ".json"
            if not os.path.exists(f"{tmpdir}/{dirname}"):
                os.mkdir(f"{tmpdir}/{dirname}")
            with open(f"{tmpdir}/{dirname}/{filename}", "w") as jsonfile:
                json.dump(result, jsonfile, sort_keys=True, indent=2)
            os.utime(
                f"{tmpdir}/{dirname}/{filename}",
                (modifiedtime.timestamp(), modifiedtime.timestamp()),
            )
        sas = generatesas()
        cmd = [
            "azcopy",
            "cp",
            tmpdir,
            f"{datalake_blob_prefix}/{blobdest}?{sas}",
            "--put-md5",
            "--overwrite=ifSourceNewer",
            "--recursive=true",
            "--as-subdir=false",
        ]
        logging.info(cmd)
        run(cmd)


@app.get("/globalQuery")
def global_query(
    query: str, tasks: BackgroundTasks, timespan: str = "P7D", count: bool = False, blobdest: str = "", loganalyticsdest: str = "", filenamekeys: str = ""
):
    """
    Query all workspaces with SecurityIncident tables using kusto.
    If blobdest is provided as a path the first 2 segments are assumed to be the location to save results to <account>/<container>/.../<filename>
    If loganalyticsdest is provided it defines a custom log table to upload results to using the LA_CUSTOMERID and LA_SHAREDKEY env vars
    Results are saved as individual .json files, and overwritten if they already exist.
    Filenamekeys are a comma separated list of keys to build filename from
    """
    results = analytics_query([ws.customerId for ws in list_workspaces()], query, timespan)
    if blobdest != "":
        tasks.add_task(upload_results, results, blobdest, filenamekeys)
    if loganalyticsdest != "":
        tasks.add_task(upload_loganalytics, results, loganalyticsdest)
    if count:
        return len(results)
    else:
        return results


@app.get("/globalStats")
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
    results = analytics_query([ws.customerId for ws in list_workspaces()], query, timespan)
    if blobdest != "":
        blobdest = blobdest.format(querydate=datetime.now().date().isoformat())
        blobdest = clean_path(blobdest)
        with tempfile.NamedTemporaryFile(mode="w") as uploadjson:
            json.dump(results, uploadjson, sort_keys=True, indent=2)
            uploadjson.flush()
            sas = generatesas()
            cmd = ["azcopy", "cp", uploadjson.name, f"{datalake_blob_prefix}/{blobdest}?{sas}", "--put-md5", "--overwrite=true"]
            logging.info(cmd)
            run(cmd)
    if count:
        return len(results)
    else:
        return results


email_template = Template(read_text(f"{__package__}.templates", "email-template.html"))


def get_datalake_file(path: str):
    path = clean_path(path)
    sas = generatesas()
    url = f"{datalake_blob_prefix}/{path}?{sas}"
    cmd = ["az", "storage", "blob", "download", "--blob-url", url, "-f", "/dev/stdout", "--max-connections", "1", "--no-progress", "-o", "none"]
    result = check_output(cmd)
    return json.loads(result)


@app.get("/sentinelBeautify")
def sentinel_beautify(blob_path: str):
    """
    Takes a SecurityIncident from sentinel, and retreives related alerts and returns markdown, html and detailed json representation.
    """
    valid_prefix = "/datalake/sentinel_outputs/incidents"
    if not blob_path.startswith(valid_prefix):
        return f"Blob path must start with {valid_prefix}"
    blob_path = blob_path[10:]  # strip leading datalake
    data = get_datalake_file(blob_path)
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
                alert = get_datalake_file(url)
            except Exception as e:  # alert may not exist on day of last activity time
                logging.warning(e)
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


# Build and send a request to the Log Analytics POST API
def upload_loganalytics(rows: list, log_type: str):
    subscription, resourcegroup, workspacename = os.environ["AZMONITOR_DATA_COLLECTOR"].split("/")
    la_customer_id = azcli(
        ["monitor", "log-analytics", "workspace", "show", "--subscription", subscription, "--resource-group", resourcegroup, "--name", workspacename]
    )["customerId"]
    la_shared_key = azcli(
        ["monitor", "log-analytics", "workspace", "get-shared-keys", "--subscription", subscription, "--resource-group", resourcegroup, "--name", workspacename]
    )["primarySharedKey"]
    table_name = f"{log_type}_CL"
    existing_data = analytics_query([la_customer_id], table_name, "P7D")  # Scan past 7 days for duplicates
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
        method = "POST"
        content_type = "application/json"
        resource = "/api/logs"

        rfc1123date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(body)
        logging.info(f"Uploading {content_length} bytes to {table_name}")
        signature = build_la_signature(la_customer_id, la_shared_key, rfc1123date, content_length, method, content_type, resource)
        uri = "https://" + la_customer_id + ".ods.opinsights.azure.com" + resource + "?api-version=2016-04-01"

        headers = {"content-type": content_type, "Authorization": signature, "Log-Type": log_type, "x-ms-date": rfc1123date}

        response = requests.post(uri, data=body, headers=headers)
        if response.status_code >= 300:
            raise HTTPException(response.status_code, response.text)
