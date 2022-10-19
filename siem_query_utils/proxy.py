import base64
from distutils.command.clean import clean
import hashlib
import json, typing
import logging
from .api import azcli, cache

import httpx, httpx_cache, os

from secrets import token_urlsafe
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=token_urlsafe(), session_cookie="fastapi_jupyterlite", same_site="strict")

sessions = {}  # global cache of sessions and async clients


@cache.memoize(ttl=60 * 60)
def httpx_client(proxy):
    # cache client objects for an hour
    client = httpx_cache.Client(**proxy, timeout=None)
    client.headers["host"] = client.base_url.host
    client.headers["accept-encoding"] = "gzip"
    return client


@cache.memoize(ttl=60 * 60)
def boot(secret):
    # cache session creds for an hour
    secret = azcli(["keyvault", "secret", "show", "--id", secret])
    if "error" in secret:
        logging.warning(secret["error"])
        raise HTTPException(403, "KEYVAULT_SESSION_SECRET not available")
    return secret["value"]


def _session(request: Request) -> dict:
    # Create or retrieve a session
    if not request.session.get("key") or "main_path" not in sessions.get(request.session["key"], {}):
        if "KEYVAULT_SESSION_SECRET" not in os.environ:
            raise HTTPException(403, "KEYVAULT_SESSION_SECRET not available")
        session_data = load_session(boot(os.environ["KEYVAULT_SESSION_SECRET"]))
        if session_data["key"] not in sessions:  # keep existing session if config the same
            sessions[session_data["key"]] = session_data
        request.session["key"] = session_data["key"]  # save ref to session in users cookie
    return sessions[request.session["key"]]["session"]


default_session = {
    "proxy_httpbin": {
        "base_url": "https://httpbin.org",
        # "params": {"get": "params"},
        # "headers": {"http": "headers"},
        # "cookies": {"cookie": "jar"},
    },
    "proxy_jupyter": {"base_url": "https://wagov.github.io/wasoc-jupyterlite"},
}


@app.get("/main_path")
def main_path(request: Request):
    return RedirectResponse(request.scope.get("root_path") + _session(request)["main_path"])


@app.post("/config")
def config(session: dict = default_session):
    """
    Basic validation for session config, to save place the
    `base64` string into the keyvault secret defined with `KEYVAULT_SESSION_SECRET`
    """
    return load_session(base64.b64encode(json.dumps(session, sort_keys=True).encode("utf8")))


def load_session(data: str, session: dict = default_session):
    """
    Decode and return a session as a json object and the base64 string for easy editing
    """
    session.update(json.loads(base64.b64decode(data)))
    session_str = json.dumps(session, sort_keys=True).encode("utf8")
    key, b64 = hashlib.sha256(session_str).hexdigest(), base64.b64encode(session_str)
    session["apis"] = {}
    for key, data in session.items():
        if key.startswith("proxy_"):
            # Validate proxy parameters
            assert httpx_client(data)
            session["apis"][key.replace("proxy_", "", 1)] = data["base_url"]
    return {"session": session, "base64": b64, "key": key}


@app.get("/apis")
def apis(request: Request) -> dict:
    return _session(request)["apis"]


def filter_headers(headers: dict, filtered_prefixes=["host", "accept-encoding", "cookie", "x-ms-", "x-arr-", "disguised-host", "referer"]):
    clean_headers = {}
    for key, value in headers.items():
        for prefix in filtered_prefixes:
            if key.lower().startswith(prefix):
                break
        else:
            clean_headers[key] = value
    return clean_headers


async def get_body(request: Request):
    # wrapper to allow sync access of body
    return await request.body()


@app.get("/{prefix}/{path:path}", response_class=Response)
def upstream(request: Request, prefix: str, path: str, body=Depends(get_body)):
    session = _session(request)
    proxy_key = f"proxy_{prefix}"
    if proxy_key not in session:
        raise HTTPException(404, f"{prefix} does not have a valid configuration, see /proxy/apis for valid prefixes.")
    client = httpx_client(session[proxy_key])
    headers = filter_headers(request.headers)
    url = httpx.URL(path=path, query=request.url.query.encode("utf-8"))
    with client.stream(request.method, url, content=body, headers=headers) as origin:
        outbound_filtered_prefixes = ["set-cookie"]
        headers = filter_headers(origin.headers, filtered_prefixes=outbound_filtered_prefixes)
        response = Response(content=b"".join(origin.iter_raw()), status_code=origin.status_code, headers=headers)
        return response
