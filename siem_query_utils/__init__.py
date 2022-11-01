import importlib
import os
from subprocess import Popen, run

import uvicorn
from dotenv import load_dotenv
from fire import Fire

load_dotenv()

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from .api import api_2, clean_path, list_workspaces
from .proxy import proxy_1

app = FastAPI(title="SIEM Query Utils Index", version=importlib.metadata.version(__package__))
app.mount("/api/v2", api_2)
app.mount("/proxy", proxy_1)


@app.get("/")
def index():
    return RedirectResponse("/proxy/main_path")


def atlaskit():
    # launch node helper on port 3000 (handle running in a non interactive session for nvm/node access)
    run(["bash", "-l", "-c", "node atlaskit-transformer/main.mjs"])


def serve():
    # launch background node helper on port 3000 (handle running in a non interactive session for nvm/node access)
    atlaskit = Popen(["bash", "-l", "-c", "node atlaskit-transformer/main.mjs"], close_fds=True)
    # serve on port 8000, assume running behind a trusted reverse proxy
    host, port = "0.0.0.0", 8000
    # Launch main uvicor server
    uvicorn.run(app, port=port, host=host, log_level=os.environ.get("LOG_LEVEL", "WARNING").lower(), proxy_headers=True)
    # Clean up node helper
    atlaskit.kill()


def jupyterlab(path: str = "."):
    # Launch jupyterlab server (default to current dir as path)
    run(["bash", "-l", "-c", "az login --tenant $TENANT_ID; jupyter lab"], cwd=clean_path(os.path.expanduser(path)))


def cli():
    Fire({"listWorkspaces": list_workspaces, "serve": serve, "jupyterlab": jupyterlab, "atlaskit": atlaskit})
