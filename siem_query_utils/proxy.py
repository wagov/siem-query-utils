import base64
import hashlib
import json
import logging
from string import Template
from subprocess import check_output
from .api import azcli

import httpx, os

from secrets import token_urlsafe
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, RedirectResponse, HTMLResponse
from fastapi.background import BackgroundTasks
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=token_urlsafe(),
    session_cookie="fastapi_jupyterlite",
    same_site="strict",
)

sessions = {}  # global cache of sessions and async clients


def _session(request: Request):
    if not request.session.get("key") in sessions:
        raise HTTPException(403, "fastapi_jupyterlite session does not exist")
    return sessions[request.session["key"]]["session"]


redirect = Template(
    """
<!DOCTYPE HTML>
 
<meta charset="UTF-8">
<meta http-equiv="refresh" content="1; url=$url">
 
<script>
  window.location.href = "$url"
</script>
 
<title>Page Redirection</title>
 
<!-- Note: don't tell people to `click` the link, just tell them that it is a link. -->
If you are not redirected automatically, follow the <a href='$url'>link</a>
"""
)


@app.get("/", response_class=HTMLResponse)
async def boot(request: Request):
    if not request.session.get("key") or not _session(request).get("main_path"):
        try:
            secret = os.environ["KEYVAULT_SESSION_SECRET"]
        except Exception as e:
            logging.warning(e)
            raise HTTPException(403)
        secret = azcli(["keyvault", "secret", "show", "--id", secret, "--only-show-errors", "-o", "json"])
        if "error" in secret:
            logging.warning(secret["error"])
            raise HTTPException(403)
        secret = secret["value"]
        await session_config(request, session_base64=secret)
    url = request.scope["root_path"] + _session(request)["main_path"]
    return HTMLResponse(redirect.substitute(url=url))


sample_session = {
    "proxy_httpbin": {
        "base_url": "https://httpbin.org",
        "params": {"get": "params"},
        "headers": {"http": "headers"},
        "cookies": {"cookie": "jar"},
    }
}


@app.post("/session_config")
async def session_config(request: Request, session: dict = sample_session, session_base64: str = ""):
    """
    If sent session as a json object, save that as the session
    If sent session_base64, decode and return as a json object and the base64 string for easy editing
    Doesn't modify an existing session if keys are the same (to preserve asyncclient cache)
    """
    if session_base64:
        session = json.loads(base64.b64decode(session_base64))
    session_str = json.dumps(session, sort_keys=True).encode("utf8")
    key, b64 = hashlib.sha256(session_str).hexdigest(), base64.b64encode(session_str)
    posted_session = {"session": session, "base64": b64, "key": key}
    if key not in sessions:  # keep existing session if config the same
        sessions[key] = posted_session
    request.session["key"] = key  # save ref to session in users cookie
    return posted_session


@app.post("/proxy_config/{proxy}")
async def proxy_config(request: Request, proxy: str, config: dict):
    session = _session(request)
    session[f"proxy_{proxy}"] = config
    await session_config(request, session)
    return await apis(request)


@app.get("/apis")
async def apis(request: Request):
    try:
        session = _session(request)
    except Exception as e:
        logging.warning(str(e))
        return RedirectResponse(request.scope["root_path"])
    apis = {}
    for key, data in session.items():
        if key.startswith("proxy_"):
            apis[key.replace("proxy_", "", 1)] = data["base_url"]
    return apis


@app.get("/{prefix}/{path:path}")
async def upstream(request: Request, prefix: str, path: str):
    try:
        session = _session(request)
    except Exception as e:
        logging.warning(str(e))
        return RedirectResponse(request.scope["root_path"])
    if prefix in ["favicon.ico"]:
        raise HTTPException(status_code=404, detail=f"{prefix} not a valid domain.")
    proxy_key = f"proxy_{prefix}"
    proxy = session.get(proxy_key, {"base_url": f"https://{prefix}"})
    client_key = f"client_{prefix}"
    client = session.get(client_key)
    if not client:
        client = httpx.AsyncClient(**proxy, timeout=None)
        session[client_key] = client
    url = httpx.URL(path=path, query=request.url.query.encode("utf-8"))
    headers = dict(request.headers)
    headers["host"] = client.base_url.host
    filtered = ["cookie", "set-cookie"]
    for header in filtered:
        if header in headers:
            headers.pop(header)
    rp_req = client.build_request(request.method, url, headers=headers, content=await request.body())
    try:
        rp_resp = await client.send(rp_req, stream=True)
    except Exception as e:
        logging.warning(str(e))
        raise HTTPException(503)
    resp_headers = rp_resp.headers
    for header in filtered:
        if header in resp_headers:
            resp_headers.pop(header)
    return StreamingResponse(
        rp_resp.aiter_raw(),
        status_code=rp_resp.status_code,
        headers=resp_headers,
        background=BackgroundTasks([rp_resp.aclose]),
    )
