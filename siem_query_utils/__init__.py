# pylint: disable=line-too-long
import importlib
import os
from secrets import token_urlsafe
from subprocess import Popen, run

import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fire import Fire
from starlette.middleware.sessions import SessionMiddleware

from . import api, proxy, sentinel_beautify

app = FastAPI(title="SIEM Query Utils API v2", version=importlib.metadata.version(__package__))
app.include_router(api.router, prefix="/api/v2", tags=["siemqueryutils"])
app.include_router(sentinel_beautify.router, prefix="/api/v2", tags=["sentinel_beautify"])
app.include_router(proxy.router, tags=["proxy"])
app.add_middleware(SessionMiddleware, secret_key=token_urlsafe(), session_cookie="siem_query_utils", same_site="strict")


@app.get("/")
def index():
    """
    Redirect to /proxy/main_path
    """
    return RedirectResponse("/main_path")


def atlaskit():
    # launch node helper on port 3000 (handle running in a non interactive session for nvm/node access)
    run(["bash", "-l", "-c", "node atlaskit-transformer/main.mjs"], check=False)


def serve():
    # launch background node helper on port 3000 (handle running in a non interactive session for nvm/node access)
    background_atlaskit = Popen(["bash", "-l", "-c", "node atlaskit-transformer/main.mjs"], close_fds=True)
    # serve on port 8000, assume running behind a trusted reverse proxy
    host, port = "0.0.0.0", 8000
    # Launch main uvicor server
    uvicorn.run(app, port=port, host=host, log_level=os.environ.get("LOG_LEVEL", "WARNING").lower(), proxy_headers=True)
    # Clean up node helper
    background_atlaskit.kill()


def jupyterlab(path: str = "."):
    # Launch jupyterlab server (default to current dir as path)
    run(["bash", "-l", "-c", "az login --tenant $TENANT_ID; jupyter lab"], cwd=api.clean_path(os.path.expanduser(path)), check=False)


def cli():
    Fire({"listWorkspaces": api.list_workspaces, "serve": serve, "jupyterlab": jupyterlab, "atlaskit": atlaskit})
