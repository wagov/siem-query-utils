"""
Proxy API
"""
# pylint: disable=line-too-long
import json
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from .azcli import default_session, encode_session, httpx_client, load_session, settings

router = APIRouter()
sessions = settings("sessions")  # global cache of sessions and async clients


def _session(request: Request, key="session") -> dict:
    # Create or retrieve a session
    if not request.session.get("key") or "main_path" not in sessions.get(request.session["key"], {}):
        session_data = settings("keyvault_session")
        if "KEYVAULT_SESSION_SECRET" not in os.environ:
            raise HTTPException(403, "KEYVAULT_SESSION_SECRET not available")
        if session_data["key"] not in sessions:  # keep existing session if config the same
            sessions[session_data["key"]] = session_data
        request.session["key"] = session_data["key"]  # save ref to session in users cookie
    return sessions[request.session["key"]][key]


@router.get("/main_path")
def main_path(request: Request) -> RedirectResponse:
    """
    Redirect to the main path for this session

    Args:
        request (Request): fastapi request object

    Returns:
        RedirectResponse: redirect to main path
    """
    return RedirectResponse(request.scope.get("root_path") + _session(request)["main_path"])


@router.post("/config_base64")
def config_base64(session: str = encode_session(json.loads(default_session))):
    """
    Basic validation for session confi in base64 format, to save place the
    `base64` string into the keyvault secret defined with `KEYVAULT_SESSION_SECRET`
    """
    return load_session(session)


@router.post("/config")
def config_dict(session: dict = json.loads(default_session)):
    """
    Basic validation for session config in json format, to save place the
    `base64` string into the keyvault secret defined with `KEYVAULT_SESSION_SECRET`
    """
    return load_session(encode_session(session))


@router.get("/apis")
def apis(request: Request) -> dict:
    """
    Return a list of configured origins and associated valid proxy prefixes

    Args:
        request (Request): fastapi request object

    Returns:
        dict: list of valid proxy prefixes
    """
    return _session(request, key="apis")


def client(request: Request, prefix: str):
    """
    Return a httpx client for the given prefix from the session config
    """
    if prefix not in apis(request):
        raise HTTPException(404, f"{prefix} does not have a valid configuration, see /proxy/apis for valid prefixes.")
    return httpx_client(_session(request)[f"proxy_{prefix}"])


def filter_headers( # pylint: disable=dangerous-default-value
    headers: dict, filtered_prefixes=["host", "cookie", "x-ms-", "x-arr-", "disguised-host", "referer"]
) -> dict:
    """
    Filter headers to remove sensitive data

    Args:
        headers (dict): headers to filter
        filtered_prefixes (list, optional): prefixes to filter. Defaults to ["host", "cookie", "x-ms-", "x-arr-", "disguised-host", "referer"].

    Returns:
        dict: filtered headers
    """
    clean_headers = {}
    for key, value in headers.items():
        for prefix in filtered_prefixes:
            if key.lower().startswith(prefix):
                break
        else:
            clean_headers[key] = value
    return clean_headers


async def get_body(request: Request):
    """
    Wrapper to get the body of a request

    Args:
        request (Request): fastapi request object

    Returns:
        bytes: body of request
    """
    return await request.body()


@router.get("/{prefix}/{path:path}", response_class=Response)
def upstream(request: Request, prefix: str, path: str, body=Depends(get_body)):
    """
    Proxies a request to the upstream API

    Args:
        request (Request): fastapi request object
        prefix (str): prefix of the upstream API
        path (str): path of the upstreams service
        body (bytes, optional): body of the request. Defaults to Depends(get_body).

    Raises:
        HTTPException: if the upstream API returns an error

    Returns:
        Response: response from the upstream API
    """
    # Proxies a request to a defined upstream as defined in session
    headers = filter_headers(request.headers)
    url = httpx.URL(path=path, query=request.url.query.encode("utf-8"))
    upstream_client = client(request, prefix)
    with upstream_client.stream(request.method, url, content=body, headers=headers) as origin:
        if "location" in origin.headers:
            base_url = f"{upstream_client.base_url}/"
            if origin.headers["location"].startswith(base_url):
                redir_path = origin.headers["location"].replace(base_url, "", 1)
                origin.headers["location"] = request.scope.get("root_path") + f"/{prefix}/{redir_path}"
            elif origin.headers["location"].startswith("http"):
                raise HTTPException(403, f"Redirect to {origin.headers['location']} not allowed.")
        response = Response(status_code=origin.status_code)
        response.body = b"".join(origin.iter_raw())
        strip_output_headers = ["set-cookie", "transfer-encoding", "content-length", "server", "date", "connection"]
        headers = filter_headers(origin.headers, filtered_prefixes=strip_output_headers)
        response.init_headers(headers=headers)
        return response
