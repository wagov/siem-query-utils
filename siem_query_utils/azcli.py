"""
Azure CLI helpers and core functions
"""
# pylint: disable=logging-fstring-interpolation, unspecified-encoding
import asyncio
import base64
import hashlib
import importlib
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from string import Template
from types import FunctionType
from concurrent.futures import ThreadPoolExecutor

import httpx_cache
from azure.cli.core import get_default_cli
from azure.storage.blob import BlobServiceClient
from cacheout import Cache
from cloudpathlib import AzureBlobClient
from dotenv import load_dotenv
from fastapi import HTTPException
from pathvalidate import sanitize_filepath
from uvicorn.config import Config

local_env = Path(".env")
if local_env.exists():
    load_dotenv(dotenv_path=local_env)


# Steal uvicorns logger config
logger = logging.getLogger("uvicorn.error")
Config(f"{__package__}:app").configure_logging()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

cache = Cache(maxsize=25600, ttl=300)


app_state = {
    "logged_in": False,
    "login_time": datetime.utcnow() - timedelta(days=1),
}  # last login 1 day ago to force relogin


default_session = json.dumps(
    {
        "proxy_httpbin": {
            "base_url": "https://httpbin.org",
            # "params": {"get": "params"},
            # "headers": {"http": "headers"},
            # "cookies": {"cookie": "jar"},
        },
        "proxy_jupyter": {"base_url": "https://wagov.github.io/wasoc-jupyterlite"},
        "main_path": "/jupyter/lab/index.html",  # this is redirected to when index is loaded
    }
)


@cache.memoize(ttl=60 * 60)
def httpx_client(proxy: dict) -> httpx_cache.Client:
    """
    Create a httpx client with caching

    Args:
        proxy (dict): proxy config

    Returns:
        httpx_cache.Client: httpx client
    """
    # cache client objects for an hour
    proxy_client = httpx_cache.Client(**proxy, timeout=None)
    proxy_client.headers["host"] = proxy_client.base_url.host
    return proxy_client


@cache.memoize(ttl=60 * 60)
def boot(secret: str) -> str:
    """
    Connect to keyvault and get the session data

    Args:
        secret (str): keyvault secret URL

    Raises:
        HTTPException: 403 if secret is not found

    Returns:
        str: session data as a base64 encoded string
    """
    # cache session creds for an hour
    secret = azcli(["keyvault", "secret", "show", "--id", secret])
    if not secret or "error" in secret:
        logger.warning(secret["error"])
        raise HTTPException(403, "KEYVAULT_SESSION_SECRET not available")
    return secret["value"]


def encode_session(session: dict) -> str:
    """
    Encode a session as a base64 string

    Args:
        session (dict): session data

    Returns:
        str: base64 encoded string
    """
    return base64.b64encode(json.dumps(session, sort_keys=True).encode("utf8"))


def load_session(data: str = None, config: dict = json.loads(default_session)):
    """
    Decode and return a session as a json object and the base64 string for easy editing
    """
    if data is None:  # for internal python use only
        data = boot(os.environ["KEYVAULT_SESSION_SECRET"])
    try:
        config.update(json.loads(base64.b64decode(data)))
    except Exception as exc:
        logger.warning(exc)
        raise HTTPException(500, "Failed to load session data") from exc
    session = {"session": config, "base64": encode_session(config), "apis": {}}
    session["key"] = hashlib.sha256(session["base64"]).hexdigest()
    for item, data in config.items():
        if item.startswith("proxy_"):
            # Validate proxy parameters
            assert httpx_client(data)
            session["apis"][item.replace("proxy_", "", 1)] = data["base_url"]
    return session


def clean_path(path: str) -> str:
    """
    Remove any disallowed characters from a path

    Args:
        path (str): path to sanitize

    Returns:
        str: sanitized path
    """
    return sanitize_filepath(path.replace("..", ""), platform="auto")


def configure_loop():
    """
    Configure shared background threads for all async functions

    Uses uvicorns default loop with a fallback to creating a new loop
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    app_state["executor"] = ThreadPoolExecutor(max_workers=int(os.environ.get("MAX_THREADS", 8)))
    loop.set_default_executor(app_state["executor"])

def submit(func, *args, **kwargs):
    """
    Submit a function to the default loop executor

    Args:
        func (function): function to run
        *args: function arguments
        **kwargs: function keyword arguments

    Returns:
        asyncio.Future: future object
    """
    if "executor" not in app_state:
        configure_loop()
    return app_state["executor"].submit(func, *args, **kwargs)

def bootstrap(_app_state: dict):
    """
    Load app state from env vars or dotenv

    Args:
        _app_state (dict): app state

    Raises:
        Exception: if essential env vars are not set
    """
    try:
        prefix, subscription = (
            os.environ["DATALAKE_BLOB_PREFIX"],
            os.environ["DATALAKE_SUBSCRIPTION"],
        )
    except Exception as exc:
        raise Exception(
            "Please set DATALAKE_BLOB_PREFIX and DATALAKE_SUBSCRIPTION env vars"
        ) from exc
    account, container = prefix.split("/")[2:]
    _app_state.update(
        {
            # datalake_blob_prefix example: "https://{datalake_account}.blob.core.windows.net/{datalake_container}"
            "datalake_blob_prefix": prefix,
            "datalake_subscription": subscription,
            "datalake_account": account,
            "datalake_container": container,
            "datalake_sas": os.environ.get("DATALAKE_SAS", False),
            "email_template": Template(
                importlib.resources.read_text(f"{__package__}.templates", "email-template.html")
            ),
            "datalake_path": lambda: get_blob_path(prefix, subscription),
            "email_footer": os.environ.get(
                "FOOTER_HTML", "Set FOOTER_HTML env var to configure this..."
            ),
            "data_collector_connstring": os.environ.get(
                "AZMONITOR_DATA_COLLECTOR"
            ),  # kinda optional
            "keyvault_session": lambda: load_session(boot(os.environ["KEYVAULT_SESSION_SECRET"]))
            if "KEYVAULT_SESSION_SECRET" in os.environ
            else None,
            "sessions": {},
        }
    )


def login(refresh: bool = False):
    """
    login to azure cli and setup app state

    Args:
        refresh (bool, optional): force relogin. Defaults to False.
    """
    cli = get_default_cli()
    if os.environ.get("IDENTITY_HEADER"):
        if refresh:
            cli.invoke(
                ["logout", "--only-show-errors", "-o", "json"], out_file=open(os.devnull, "w")
            )
        # Use managed service identity to login
        loginstatus = cli.invoke(
            ["login", "--identity", "--only-show-errors", "-o", "json"],
            out_file=open(os.devnull, "w"),
        )
        if cli.result.error:
            # bail as we aren't able to login
            logger.error(cli.result.error)
            exit(loginstatus)
        app_state["logged_in"] = True
        app_state["login_time"] = datetime.utcnow()
    else:  # attempt interactive login
        while not app_state["logged_in"]:
            cli.invoke(["account", "show", "-o", "json"], out_file=open(os.devnull, "w"))
            if cli.result.result and "environmentName" in cli.result.result:
                app_state["logged_in"] = True
                app_state["login_time"] = datetime.utcnow()
            else:
                cli.invoke(
                    ["login", "--tenant", os.environ["TENANT_ID"], "--use-device-code"],
                    out_file=open(os.devnull, "w"),
                )
    # setup all other env vars
    bootstrap(app_state)


def settings(key: str):
    """
    Get a setting from the app state.
    Lazily evaluates app state defined as functions and cache the results

    Args:
        key (str): setting key

    Returns:
        setting value
    """
    if datetime.utcnow() - app_state["login_time"] > timedelta(hours=1):
        login(refresh=True)
    elif not app_state["logged_in"]:
        login()
    setting = app_state[key]
    if isinstance(setting, FunctionType):
        setting = setting()
        app_state[key] = setting
    return app_state[key]


@cache.memoize(ttl=60)
def azcli(basecmd: list, attempt: int = 0, max_attempts: int = 5):
    """
    Run a general azure cli cmd with retries

    Args:
        basecmd (list): base command to run
        attempt (int, optional): attempt number. Defaults to 0.
        max_attempts (int, optional): max attempts. Defaults to 5.

    Returns:
        dict: json response from cli invocation
    """
    assert settings("logged_in")
    cmd = basecmd + ["--only-show-errors", "-o", "json"]
    cli = get_default_cli()
    for arg in cmd:
        assert isinstance(arg, str)
    logger.debug(" ".join(["az"] + cmd).replace("\n", " ").strip()[:160])
    try:
        cli.invoke(cmd, out_file=open(os.devnull, "w"))
    except (SystemExit, Exception) as exc:  # pylint: disable=broad-except
        if attempt >= max_attempts:
            raise Exception(f"Exceeded {max_attempts} CLI invocations") from exc
        logger.warning(f"CLI invocation failed: attempt {attempt}, retrying... ({exc})")
        time.sleep(1 + attempt * 2)  # exponential backoff
        return azcli(basecmd, attempt + 1, max_attempts)
    if cli.result.error:
        logger.warning(cli.result.error)
    return cli.result.result


@cache.memoize(ttl=60 * 60 * 24)  # cache sas tokens 1 day
def generatesas(
    account: str = None,
    container: str = None,
    subscription: str = None,
    permissions="racwdlt",
    expiry_days=3,
) -> str:
    """
    Generate a SAS token for a storage account

    Args:
        account (str, optional): storage account name. Defaults to None.
        container (str, optional): container name. Defaults to None.
        subscription (str, optional): subscription id. Defaults to None.
        permissions (str, optional): SAS permissions. Defaults to "racwdlt".
        expiry_days (int, optional): SAS expiry in days. Defaults to 3.

    Returns:
        str: SAS token
    """
    expiry = str(datetime.today().date() + timedelta(days=expiry_days))
    if not (account and container and subscription):
        account = settings("datalake_account")
        container = settings("datalake_container")
        subscription = settings("datalake_subscription")
    result = azcli(
        [
            "storage",
            "container",
            "generate-sas",
            "--auth-mode",
            "login",
            "--as-user",
            "--account-name",
            account,
            "-n",
            container,
            "--subscription",
            subscription,
            "--permissions",
            permissions,
            "--expiry",
            expiry,
        ]
    )
    logger.debug(result)
    return result


def get_blob_path(url: str, subscription: str = ""):
    """
    Mounts a blob url using azure cli
    If called with no subscription, just returns a pathlib.Path pointing to url (for testing)
    """
    if subscription == "":
        return Path(clean_path(url))
    account, container = url.split("/")[2:]
    account = account.split(".")[0]
    if url == settings("datalake_blob_prefix") and settings("datalake_sas"):
        sas = settings("datalake_sas")  # use preset sas token if available
    else:
        sas = generatesas(account, container, subscription)
    blobclient = AzureBlobClient(
        blob_service_client=BlobServiceClient(
            account_url=url.replace(f"/{container}", ""), credential=sas
        )
    )
    return blobclient.CloudPath(f"az://{container}")
