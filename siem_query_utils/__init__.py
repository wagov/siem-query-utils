import importlib
import os

import uvicorn
from dotenv import load_dotenv
from fire import Fire

load_dotenv()

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from .api import (api_1, api_2, global_query, global_stats, list_workspaces,
                  simple_query)
from .proxy import proxy_1

app = FastAPI(title="SIEM Query Utils Index", version=importlib.metadata.version(__package__))
app.mount("/api/v1", api_1)
app.mount("/api/v2", api_2)
app.mount("/proxy", proxy_1)


@app.get("/")
def index():
    return RedirectResponse("/proxy/main_path")


def serve():
    # serve on port 8000, assume running behind a trusted reverse proxy
    host, port = "0.0.0.0", 8000
    uvicorn.run(app, port=port, host=host, log_level=os.environ.get("LOG_LEVEL", "WARNING").lower(), proxy_headers=True)


def cli():
    Fire({"listWorkspaces": list_workspaces, "simpleQuery": simple_query, "globalQuery": global_query, "globalStats": global_stats, "serve": serve})
