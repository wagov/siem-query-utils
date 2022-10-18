import base64
from distutils.command.clean import clean
import hashlib
import json
import logging
from .api import azcli, cache

import httpx, httpx_cache, os

from secrets import token_urlsafe
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, RedirectResponse
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware


app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=token_urlsafe(),
    session_cookie="fastapi_jupyterlite",
    same_site="strict",
)
app.add_middleware(GZipMiddleware)

sessions = {}  # global cache of sessions and async clients


@cache.memoize(ttl=60 * 60)
def httpx_client(proxy):
    # cache client objects for an hour
    return httpx_cache.Client(**proxy, timeout=None)


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
        session_config(request, session_base64=boot(os.environ["KEYVAULT_SESSION_SECRET"]))
    return sessions[request.session["key"]]["session"]


sample_session = {
    "proxy_httpbin": {
        "base_url": "https://httpbin.org",
        "params": {"get": "params"},
        "headers": {"http": "headers"},
        "cookies": {"cookie": "jar"},
    }
}


@app.get("/main_path")
def main_path(request: Request):
    return RedirectResponse(request.scope.get("root_path") + _session(request)["main_path"])


@app.post("/session_config")
def session_config(request: Request, session: dict = sample_session, session_base64: str = ""):
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
    session = _session(request)
    apis = {}
    for key, data in session.items():
        if key.startswith("proxy_"):
            apis[key.replace("proxy_", "", 1)] = data["base_url"]
    return apis


def filter_headers(
    headers: dict,
    filtered_prefixes=[
        "cookie",
        "set-cookie",
        "x-ms-",
        "x-arr-",
        "disguised-host",
        "referer",
        "content-length",
        "content-encoding",
        "accept-encoding",
    ],
):
    clean_headers = {}
    for key, value in headers.items():
        for prefix in filtered_prefixes:
            if key.lower().startswith(prefix):
                break
        else:
            clean_headers[key] = value
    return clean_headers


def upstream_request(proxy: dict, method: str, url: str, headers: dict, content: bytes) -> httpx.Response:
    client = httpx_client(proxy)
    headers = filter_headers(headers)
    headers["host"] = client.base_url.host
    headers["accept-encoding"] = "gzip"
    response = client.request(method, url, content=content, headers=headers)
    response.headers = filter_headers(response.headers)
    return response


async def get_body(request: Request):
    return await request.body()


@app.get("/{prefix}/{path:path}", response_class=Response)
def upstream(request: Request, prefix: str, path: str, body=Depends(get_body)):
    session = _session(request)
    proxy_key = f"proxy_{prefix}"
    upstream_response = upstream_request(
        proxy=session.get(proxy_key, {"base_url": f"https://{prefix}"}),
        method=request.method,
        url=httpx.URL(path=path, query=request.url.query.encode("utf-8")),
        headers=request.headers,
        content=body,
    )
    response = Response(content=upstream_response.content, status_code=upstream_response.status_code, headers=upstream_response.headers)
    return response
