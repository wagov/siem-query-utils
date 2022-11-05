"""
Main entry point for the CLI and uvicorn server
"""
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
app.include_router(api.router, prefix="/api/v2", tags=["siem_query_utils"])
app.include_router(sentinel_beautify.router, prefix="/api/v2", tags=["sentinel_beautify"])
app.include_router(proxy.router, tags=["proxy"])
app.add_middleware(
    SessionMiddleware,
    secret_key=token_urlsafe(),
    session_cookie="siem_query_utils",
    same_site="strict",
)


@app.get("/")
def index():
    """
    Redirect to /proxy/main_path
    """
    return RedirectResponse("/main_path")


def atlaskit(execute=True):
    """
    launch node helper on port 3000 (handle running in a non interactive session for nvm/node access).
    """
    node_module = importlib.resources.path(f"{__package__}.js", "atlaskit-transformer.mjs")
    cmd = [node_module.resolve()]
    if execute:
        run(cmd, check=False)
    return cmd


def serve():
    """
    launch uvicorn server on port 8000 and node helper on port 3000 (handle running in a non interactive session for nvm/node access).
    assumes you have already run `az login` and `az account set` to set the correct subscription.
    its recommended to run this behind a reverse proxy like nginx or traefik.
    """
    background_atlaskit = Popen(atlaskit(execute=False), close_fds=True)
    host, port, log_level = "0.0.0.0", 8000, os.environ.get("LOG_LEVEL", "WARNING").lower()
    uvicorn.run(
        f"{__package__}:app",
        port=port,
        host=host,
        log_level=log_level,
        proxy_headers=True,
        reload=log_level == "debug",
        workers=os.cpu_count() * 2 + 1,
    )
    background_atlaskit.kill()


def jupyterlab(path: str = "."):
    """
    Launch jupyterlab in the current directory

    Args:
        path (str, optional): Path to launch jupyterlab in. Defaults to ".".
    """
    run(
        ["bash", "-i", "-c", "jupyter lab"],
        cwd=api.clean_path(os.path.expanduser(path)),
        check=False,
    )


def cli():
    """
    Entry point for the CLI to launch uvicorn server or jupyterlab
    """
    Fire(
        {
            "listWorkspaces": api.list_workspaces,
            "serve": serve,
            "jupyterlab": jupyterlab,
            "atlaskit": atlaskit,
        }
    )
