"""
Main entry point for the CLI and uvicorn server
"""
import importlib
import os
from inspect import cleandoc
from secrets import token_urlsafe
from subprocess import Popen, run
import logging

from apscheduler.schedulers.background import BackgroundScheduler

import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fire import Fire
from starlette.middleware.sessions import SessionMiddleware

from . import api, proxy, sentinel_beautify
from .azcli import configure_loop, logger

logging.getLogger("apscheduler").setLevel(logging.INFO)


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


def generate_reports():
    """
    Generate reports for all workspaces
    """
    api.collect_report_json(agency="ALL", max_age=7200)
    api.papermill_report(agency="ALL", max_age=7200)


@app.get("/")
def index():
    """
    Redirect to /docs
    """
    return RedirectResponse("/docs")


def schedule_jobs():
    logger.debug("Job scheduling enabled!!!")
    scheduler = BackgroundScheduler({"apscheduler.timezone": "Australia/Perth"})
    # Add schedules, configure tasks here
    scheduler.add_job(api.update_jira_issues, "cron", second="*/20", max_instances=1)
    scheduler.add_job(api.ingest_datalake_hot, "cron", second="*/30", max_instances=1)
    scheduler.add_job(api.export_jira_issues, "cron", minute="*/15", max_instances=1)
    scheduler.add_job(api.list_workspaces, "cron", minute="10")
    scheduler.add_job(generate_reports, "cron", hour="18", max_instances=1)
    scheduler.add_job(api.configure_datalake_hot, "cron", hour="22")
    scheduler.start()


def serve():
    """
    launch uvicorn server on port 8000 and node helper on port 3000 (handle running in a non interactive session for nvm/node access).
    assumes you have already run `az login` and `az account set` to set the correct subscription.
    its recommended to run this behind a reverse proxy like nginx or traefik.
    """
    background_atlaskit = Popen(["bash", "-l", "-c", "node ."], close_fds=True)
    if os.environ.get("SCHEDULE_JOBS", "false").lower() == "true":
        schedule_jobs()
    host, port, log_level = "0.0.0.0", 8000, os.environ.get("LOG_LEVEL", "WARNING").lower()
    # kill placeholder server before starting uvicorn
    if os.environ.get("KILL_PLACEHOLDER", "false").lower() == "true":
        run(f"pkill -f http.server", shell=True)
    uvicorn.run(
        f"{__package__}:app",
        port=port,
        host=host,
        log_level=log_level,
        proxy_headers=True,
        log_config=None,
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
            "ingest": api.ingest_datalake_hot,
        }
    )
