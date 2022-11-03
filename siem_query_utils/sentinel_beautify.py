import json

from flatten_json import flatten
from markdown import markdown
from fastapi import APIRouter

from .api import (OutputFormat, atlaskit_client, config, datalake_json,
                  list_workspaces, logger)

router = APIRouter()

@router.get("/sentinelBeautify")
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
            product_names = ",".join(data["AdditionalData"]["alertProductNames"])
            labels.append(f"SIEM_alertProductNames:{product_names}")
            incident_details.append(f"- **Product Names:** {product_names}")
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
            except Exception as exc:  # alert may not exist on day of last activity time
                logger.warning(exc)
                break
            else:
                if not alert_details:
                    alert_details += ["", "## Alert Details", "The last day of activity (up to 20 alerts) is summarised below from newest to oldest."]
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
        workspaces_df = list_workspaces(OutputFormat.DF)
        customer = workspaces_df[workspaces_df["customerId"] == data["TenantId"]].fillna("").to_dict("records")
        if len(customer) > 0:
            customer = customer[0]
        else:
            customer = {}
        # Grab wiki format for jira and truncate to 32767 chars
        response.update(
            {
                "secops_status": customer.get("SecOps Status") or default_status,
                "jira_orgid": customer.get("JiraOrgId") or default_orgid,
                "customer": customer,
                "wikimarkup": atlaskit_client().post("/md/to/wiki", content=mdtext, headers={"content-type": "text/plain"}).content[:32760],
            }
        )
    else:
        response.update({"html": html, "markdown": mdtext})
    return response
