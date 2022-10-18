import uvicorn, os
from fire import Fire
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from .api import list_workspaces, simple_query, global_query, global_stats
from .api import app as api
from .proxy import app as proxy

app = FastAPI()
app.mount("/api/v1", api)
app.mount("/proxy", proxy)


@app.get("/")
def index():
    return RedirectResponse("/proxy/main_path")


def serve():
    # serve on port 8000, assume running behind a trusted reverse proxy
    host, port = "0.0.0.0", 8000
    uvicorn.run(app, port=port, host=host, log_level=os.environ.get("LOG_LEVEL", "warning"), proxy_headers=True)


def cli():
    Fire({"listWorkspaces": list_workspaces, "simpleQuery": simple_query, "globalQuery": global_query, "globalStats": global_stats, "serve": serve})
