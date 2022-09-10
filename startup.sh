#!/bin/bash
PORT="${FUNCTIONS_CUSTOMHANDLER_PORT:-8000}"
gunicorn -b 0.0.0.0:$PORT -k uvicorn.workers.UvicornH11Worker main:app