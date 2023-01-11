"""
Main entry point for the CLI and uvicorn server
"""
import importlib
import os
from inspect import cleandoc
from secrets import token_urlsafe
from subprocess import Popen, run

import schedule
import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fire import Fire
from starlette.middleware.sessions import SessionMiddleware

from . import api, proxy, sentinel_beautify
from .azcli import configure_loop

app = FastAPI(
    title="SIEM Query Utils API v2",
    version=importlib.metadata.version(__package__),
    description=cleandoc(
        """
        ## Welcome to SIEM Query Utils API v2
        **[Code on Github](https://github.com/wagov/siem-query-utils)**.

        Please see the local [JupyterLite](/main_path) instance as a convenient way to access the below apis.

        - The below endpoints are convenient ways to query Azure Sentinel and Azure Log Analytics.
        - The /proxy endpoint can be used to proxy certain requests to pre-authenticated origins.
        """
    ),
)
app.include_router(api.router, prefix="/api/v2", tags=["siem_query_utils"])
app.include_router(sentinel_beautify.router, prefix="/api/v2", tags=["sentinel_beautify"])
app.include_router(proxy.router, tags=["proxy"])
app.add_middleware(
    SessionMiddleware,
    secret_key=token_urlsafe(),
    session_cookie="siem_query_utils",
    same_site="strict",
)

# Configures default executor including number of threads when running uvicorn
app.on_event("startup")(configure_loop)

if os.environ.get("SCHEDULE_JOBS", "false").lower() == "true":
    # register regular background tasks
    schedule.every(1).days.do(api.configure_datalake_hot)
    schedule.every(1).hours.do(api.list_workspaces)
    schedule.every(10).seconds.do(api.ingest_datalake_hot)


@app.get("/")
def index():
    """
    Redirect to /docs
    """
    return RedirectResponse("/docs")


@app.get("/run_pending")
def run_pending():
    schedule.run_pending()
    return {"jobs": [str(job) for job in schedule.get_jobs()]}


@app.get("/jobs")
def jobs():
    return {"jobs": [str(job) for job in schedule.get_jobs()]}


def serve():
    """
    launch uvicorn server on port 8000 and node helper on port 3000 (handle running in a non interactive session for nvm/node access).
    assumes you have already run `az login` and `az account set` to set the correct subscription.
    its recommended to run this behind a reverse proxy like nginx or traefik.
    """
    background_atlaskit = Popen(["bash", "-i", "-c", "node ."], close_fds=True)
    background_jobs = Popen(
        [
            "bash",
            "-c",
            "while true; do curl -s -o /dev/null http://localhost:8000/run_pending; sleep 15; done",
        ],
        close_fds=True,
    )
    host, port, log_level = "0.0.0.0", 8000, os.environ.get("LOG_LEVEL", "WARNING").lower()
    uvicorn.run(f"{__package__}:app", port=port, host=host, log_level=log_level, proxy_headers=True)
    background_atlaskit.kill()
    background_jobs.kill()


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
    Fire({"listWorkspaces": api.list_workspaces, "serve": serve, "jupyterlab": jupyterlab})
