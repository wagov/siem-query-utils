import logging, json, hashlib, pathlib, os
from string import Template
import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Beautifying sentinel json and adding html and markdown representations')

    data = req.get_json()
    labels = [
        f"SIEM_Severity:{data['Severity']}",
        f"SIEM_Status:{data['Status']}",
        f"SIEM_Title:{data['Title']}",
    ]    
    
    if data.get("Classification"):
        labels.append(f"SIEM_Classification:{data['Classification']}")
    if data.get("ClassificationReason"):
        labels.append(f"SIEM_ClassificationReason:{data['ClassificationReason']}")
    if data.get("ProviderName"):
        labels.append(f"SIEM_ProviderName:{data['ProviderName']}")
    
    if data.get("Owner"):
        data["Owner"] = json.loads(data["Owner"])
        if data["Owner"].get("email"):
            labels.append(f"SIEM_OwnerEmail:{data['Owner']['email']}")
    
    if data.get("AdditionalData"):
        data["AdditionalData"] = json.loads(data["AdditionalData"])
        if data["AdditionalData"].get("alertProductNames"):
            labels.append(f"SIEM_alertProductNames:{','.join(data['AdditionalData']['alertProductNames'])}")
        if data["AdditionalData"].get("tactics"):
            labels.append(f"SIEM_tactics:{','.join(data['AdditionalData']['tactics'])}")
        if data["AdditionalData"].get("techniques"):
            labels.append(f"SIEM_techniques:{','.join(data['AdditionalData']['techniques'])}")

    urlhash = hashlib.new('sha256')
    urlhash.update(data['IncidentUrl'].encode("utf-8"))
    urlhash = urlhash.hexdigest()
    subject = f"Sentinel Detection - {data['Title']} ({data['Status']}) - urlhash:{urlhash}"
    emailTemplate = Template(open(pathlib.Path(__file__).parent / 'email-template.html').read())
    content = f"Sentinel Incident: <a href='{data['IncidentUrl']}'>{data['Title']}</a>"
    footer = os.environ.get("FOOTER_HTML", "Set FOOTER_HTML env var to configure this...")
    html = emailTemplate.substitute(title=subject, content=content, footer=footer)

    response = {
        "subject": subject,
        "html": html,
        "labels": labels,
        "urlhash": urlhash,
        "sentinel_data": data
    }

    return func.HttpResponse(json.dumps(response), mimetype="application/json")