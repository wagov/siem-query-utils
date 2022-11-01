#!/bin/bash
curl -sSL https://install.python-poetry.org | python3 -
poetry install
poetry run az extension add -n log-analytics -y
cd atlaskit-transformer && npm clean-install
