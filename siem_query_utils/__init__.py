"""
Main entry point for the CLI and dagster server
"""
import os
import sys
from subprocess import Popen, run


def serve():
    """
    launch dagit ui on port 8000 and node helper on port 3000 (handle running in a non interactive session for nvm/node access).
    assumes you have already run `az login` and `az account set` to set the correct subscription.
    its recommended to run this behind a reverse proxy like nginx or traefik.
    """
    background_atlaskit = Popen(["bash", "-l", "-c", "node ."], close_fds=True)
    for cmd in ["prefect profile create squ-local", "prefect profile use squ-local"]:
        run(cmd, shell=True)
    # kill placeholder server before starting prefect
    if os.environ.get("KILL_PLACEHOLDER", "false").lower() == "true":
        run(f"pkill -f http.server", shell=True)
    # placeholder
    env = os.environ.copy()
    env.update({"PREFECT_ORION_API_PORT": "8000"})
    run(
        f"prefect agent start -q default -l 4 & prefect orion start; pkill -f prefect",
        shell=True,
        env=env,
    )
    background_atlaskit.kill()


def cli():
    """
    Entry point for the CLI to launch uvicorn server or jupyterlab
    """
    if sys.argv[1] == "serve":
        serve()
    elif sys.argv[1] == "jupyterlab":
        run("export $(xargs <.env); jupyter lab", shell=True, cwd=".", check=False)
    else:
        print("Invalid command. Valid commands are: serve, jupyterlab")
