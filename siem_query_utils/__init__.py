import uvicorn, os
from fire import Fire
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from .api import list_workspaces, simple_query, global_query, global_stats
from .api import app as api
from .proxy import app as proxy

app = FastAPI()
app.mount("/api/v1", api)
app.mount("/proxy", proxy)


def serve():
    host, port = "0.0.0.0", 8000
    uvicorn.run(
        app, port=port, host=host, log_level=os.environ.get("LOG_LEVEL", "info")
    )

def cli():
    Fire(
        {
            "listWorkspaces": list_workspaces,
            "simpleQuery": simple_query,
            "globalQuery": global_query,
            "globalStats": global_stats,
            "serve": serve
        }
    )